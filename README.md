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

The following list was automatically generated on Wed Jun 10 09:10:02 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|181943 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|30139 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|14825 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3012 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|3468 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|942 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2511 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|19046 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|80 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|3304 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|175 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6449 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1720 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|434 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|123 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6449 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|999 subnets, 18343755 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|509 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1718 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6340 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|104 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)|ipv4 hash:net|18393 subnets, 82416 unique IPs|updated every 1 min  from [this link]()
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5146 subnets, 688981376 unique IPs|updated every 1 min  from [this link]()
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|24120 subnets, 35737 unique IPs|updated every 1 min  from [this link]()
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)|ipv4 hash:net|109898 subnets, 9627580 unique IPs|updated every 1 min  from [this link]()
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|11912 subnets, 12152 unique IPs|updated every 1 min  from [this link]()
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|39997 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|167 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2854 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7028 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|697 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|403 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|666 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|378 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|661 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1438 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1191 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2703 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7484 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1340 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|10254 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18340608 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|375 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6941 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|93938 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29338 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|27 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10522 subnets, 10934 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2148 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
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
[openbl_60d](#openbl_60d)|7028|7028|6999|99.5%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6261|0.0%|3.4%|
[et_block](#et_block)|999|18343755|6045|0.0%|3.3%|
[firehol_level3](#firehol_level3)|109898|9627580|5208|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4218|0.0%|2.3%|
[firehol_level1](#firehol_level1)|5146|688981376|3566|0.0%|1.9%|
[openbl_30d](#openbl_30d)|2854|2854|2831|99.1%|1.5%|
[dshield](#dshield)|20|5120|2052|40.0%|1.1%|
[firehol_level2](#firehol_level2)|24120|35737|1444|4.0%|0.7%|
[blocklist_de](#blocklist_de)|30139|30139|1376|4.5%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1373|0.0%|0.7%|
[shunlist](#shunlist)|1340|1340|1328|99.1%|0.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|1147|34.7%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1110|64.5%|0.6%|
[et_compromised](#et_compromised)|1718|1718|1109|64.5%|0.6%|
[openbl_7d](#openbl_7d)|697|697|686|98.4%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|434|434|417|96.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|289|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|205|0.2%|0.1%|
[voipbl](#voipbl)|10522|10934|192|1.7%|0.1%|
[openbl_1d](#openbl_1d)|167|167|157|94.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|132|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|116|1.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|103|0.3%|0.0%|
[sslbl](#sslbl)|375|375|66|17.6%|0.0%|
[zeus](#zeus)|231|231|62|26.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|61|0.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|56|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|48|0.6%|0.0%|
[nixspam](#nixspam)|39997|39997|46|0.1%|0.0%|
[dm_tor](#dm_tor)|6449|6449|41|0.6%|0.0%|
[bm_tor](#bm_tor)|6449|6449|40|0.6%|0.0%|
[et_tor](#et_tor)|6340|6340|39|0.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|38|18.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|38|1.5%|0.0%|
[firehol_proxies](#firehol_proxies)|11912|12152|35|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|35|20.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|21|26.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|20|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|20|0.6%|0.0%|
[php_commenters](#php_commenters)|403|403|18|4.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|14|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|12|3.1%|0.0%|
[malc0de](#malc0de)|338|338|11|3.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|9|0.9%|0.0%|
[php_dictionary](#php_dictionary)|666|666|8|1.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|8|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[xroxy](#xroxy)|2148|2148|5|0.2%|0.0%|
[php_spammers](#php_spammers)|661|661|5|0.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|4|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|4|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|3|0.1%|0.0%|
[proxz](#proxz)|1191|1191|3|0.2%|0.0%|
[proxyrss](#proxyrss)|1438|1438|3|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|3|2.4%|0.0%|
[feodo](#feodo)|104|104|2|1.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Wed Jun 10 08:56:05 UTC 2015.

The ipset `blocklist_de` has **30139** entries, **30139** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24120|35737|30139|84.3%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|19046|100.0%|63.1%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|14825|100.0%|49.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3902|0.0%|12.9%|
[firehol_level3](#firehol_level3)|109898|9627580|3828|0.0%|12.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|3466|99.9%|11.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|3295|99.7%|10.9%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|3012|100.0%|9.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2538|2.7%|8.4%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|2511|100.0%|8.3%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2267|7.7%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1596|0.0%|5.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1540|0.0%|5.1%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|1384|19.9%|4.5%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|1376|0.7%|4.5%|
[openbl_60d](#openbl_60d)|7028|7028|1001|14.2%|3.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|940|99.7%|3.1%|
[nixspam](#nixspam)|39997|39997|924|2.3%|3.0%|
[openbl_30d](#openbl_30d)|2854|2854|801|28.0%|2.6%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|689|40.0%|2.2%|
[et_compromised](#et_compromised)|1718|1718|658|38.3%|2.1%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|624|0.7%|2.0%|
[firehol_proxies](#firehol_proxies)|11912|12152|613|5.0%|2.0%|
[shunlist](#shunlist)|1340|1340|460|34.3%|1.5%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|424|5.6%|1.4%|
[openbl_7d](#openbl_7d)|697|697|392|56.2%|1.3%|
[proxyrss](#proxyrss)|1438|1438|232|16.1%|0.7%|
[firehol_level1](#firehol_level1)|5146|688981376|225|0.0%|0.7%|
[et_block](#et_block)|999|18343755|212|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|208|2.0%|0.6%|
[xroxy](#xroxy)|2148|2148|207|9.6%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|202|0.0%|0.6%|
[proxz](#proxz)|1191|1191|177|14.8%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|175|100.0%|0.5%|
[openbl_1d](#openbl_1d)|167|167|126|75.4%|0.4%|
[php_dictionary](#php_dictionary)|666|666|102|15.3%|0.3%|
[php_spammers](#php_spammers)|661|661|99|14.9%|0.3%|
[php_commenters](#php_commenters)|403|403|99|24.5%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|78|2.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|61|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|61|76.2%|0.2%|
[ciarmy](#ciarmy)|434|434|40|9.2%|0.1%|
[php_harvesters](#php_harvesters)|378|378|38|10.0%|0.1%|
[voipbl](#voipbl)|10522|10934|28|0.2%|0.0%|
[dshield](#dshield)|20|5120|15|0.2%|0.0%|
[et_tor](#et_tor)|6340|6340|10|0.1%|0.0%|
[dm_tor](#dm_tor)|6449|6449|10|0.1%|0.0%|
[bm_tor](#bm_tor)|6449|6449|10|0.1%|0.0%|
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

The last time downloaded was found to be dated: Wed Jun 10 08:56:06 UTC 2015.

The ipset `blocklist_de_apache` has **14825** entries, **14825** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24120|35737|14825|41.4%|100.0%|
[blocklist_de](#blocklist_de)|30139|30139|14825|49.1%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|11059|58.0%|74.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|3465|99.9%|23.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2343|0.0%|15.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1333|0.0%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1104|0.0%|7.4%|
[firehol_level3](#firehol_level3)|109898|9627580|310|0.0%|2.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|223|0.2%|1.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|136|0.4%|0.9%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|132|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|74|1.0%|0.4%|
[shunlist](#shunlist)|1340|1340|36|2.6%|0.2%|
[ciarmy](#ciarmy)|434|434|35|8.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|33|18.8%|0.2%|
[php_commenters](#php_commenters)|403|403|31|7.6%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|28|0.2%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|22|0.7%|0.1%|
[nixspam](#nixspam)|39997|39997|18|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|15|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5146|688981376|9|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|9|0.1%|0.0%|
[dm_tor](#dm_tor)|6449|6449|9|0.1%|0.0%|
[bm_tor](#bm_tor)|6449|6449|9|0.1%|0.0%|
[et_block](#et_block)|999|18343755|8|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|7|1.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11912|12152|7|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7028|7028|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|4|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.0%|
[openbl_7d](#openbl_7d)|697|697|2|0.2%|0.0%|
[openbl_1d](#openbl_1d)|167|167|2|1.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Wed Jun 10 08:56:09 UTC 2015.

The ipset `blocklist_de_bots` has **3012** entries, **3012** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24120|35737|3012|8.4%|100.0%|
[blocklist_de](#blocklist_de)|30139|30139|3012|9.9%|100.0%|
[firehol_level3](#firehol_level3)|109898|9627580|2200|0.0%|73.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2162|2.3%|71.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2056|7.0%|68.2%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|1307|18.8%|43.3%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|504|0.6%|16.7%|
[firehol_proxies](#firehol_proxies)|11912|12152|503|4.1%|16.6%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|351|4.6%|11.6%|
[proxyrss](#proxyrss)|1438|1438|231|16.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|177|0.0%|5.8%|
[xroxy](#xroxy)|2148|2148|152|7.0%|5.0%|
[proxz](#proxz)|1191|1191|147|12.3%|4.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|129|73.7%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|97|0.0%|3.2%|
[php_commenters](#php_commenters)|403|403|79|19.6%|2.6%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|74|2.7%|2.4%|
[firehol_level1](#firehol_level1)|5146|688981376|60|0.0%|1.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|56|0.0%|1.8%|
[et_block](#et_block)|999|18343755|56|0.0%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|53|0.0%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|32|0.0%|1.0%|
[php_harvesters](#php_harvesters)|378|378|27|7.1%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|22|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|22|0.1%|0.7%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|20|0.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|20|0.0%|0.6%|
[php_spammers](#php_spammers)|661|661|17|2.5%|0.5%|
[nixspam](#nixspam)|39997|39997|17|0.0%|0.5%|
[php_dictionary](#php_dictionary)|666|666|16|2.4%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7028|7028|5|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Wed Jun 10 08:42:22 UTC 2015.

The ipset `blocklist_de_bruteforce` has **3468** entries, **3468** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24120|35737|3466|9.6%|99.9%|
[blocklist_de](#blocklist_de)|30139|30139|3466|11.5%|99.9%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|3465|23.3%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|252|0.0%|7.2%|
[firehol_level3](#firehol_level3)|109898|9627580|97|0.0%|2.7%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|75|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|69|0.0%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|62|0.2%|1.7%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|44|0.6%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|42|0.0%|1.2%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|24|0.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|20|0.0%|0.5%|
[nixspam](#nixspam)|39997|39997|17|0.0%|0.4%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|13|0.0%|0.3%|
[php_commenters](#php_commenters)|403|403|10|2.4%|0.2%|
[et_tor](#et_tor)|6340|6340|8|0.1%|0.2%|
[php_spammers](#php_spammers)|661|661|7|1.0%|0.2%|
[dm_tor](#dm_tor)|6449|6449|7|0.1%|0.2%|
[bm_tor](#bm_tor)|6449|6449|7|0.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|7|4.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|6|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|11912|12152|6|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5146|688981376|5|0.0%|0.1%|
[et_block](#et_block)|999|18343755|5|0.0%|0.1%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.0%|
[shunlist](#shunlist)|1340|1340|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Wed Jun 10 08:42:15 UTC 2015.

The ipset `blocklist_de_ftp` has **942** entries, **942** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24120|35737|941|2.6%|99.8%|
[blocklist_de](#blocklist_de)|30139|30139|940|3.1%|99.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|125|0.0%|13.2%|
[firehol_level3](#firehol_level3)|109898|9627580|17|0.0%|1.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|11|0.0%|1.1%|
[nixspam](#nixspam)|39997|39997|9|0.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|9|0.0%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|8|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|7|0.0%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|4|0.0%|0.4%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.3%|
[ciarmy](#ciarmy)|434|434|2|0.4%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|2|1.1%|0.2%|
[openbl_7d](#openbl_7d)|697|697|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7028|7028|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2854|2854|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|1|0.0%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Wed Jun 10 08:56:07 UTC 2015.

The ipset `blocklist_de_imap` has **2511** entries, **2511** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24120|35737|2511|7.0%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|2511|13.1%|100.0%|
[blocklist_de](#blocklist_de)|30139|30139|2511|8.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|318|0.0%|12.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|50|0.0%|1.9%|
[firehol_level3](#firehol_level3)|109898|9627580|45|0.0%|1.7%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|38|0.0%|1.5%|
[openbl_60d](#openbl_60d)|7028|7028|27|0.3%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|24|0.0%|0.9%|
[openbl_30d](#openbl_30d)|2854|2854|23|0.8%|0.9%|
[nixspam](#nixspam)|39997|39997|18|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|13|0.0%|0.5%|
[firehol_level1](#firehol_level1)|5146|688981376|13|0.0%|0.5%|
[et_block](#et_block)|999|18343755|13|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|12|0.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|7|0.0%|0.2%|
[openbl_7d](#openbl_7d)|697|697|7|1.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|4|0.0%|0.1%|
[et_compromised](#et_compromised)|1718|1718|3|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|3|0.1%|0.1%|
[shunlist](#shunlist)|1340|1340|2|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11912|12152|2|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|2|0.0%|0.0%|
[xroxy](#xroxy)|2148|2148|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|167|167|1|0.5%|0.0%|
[ciarmy](#ciarmy)|434|434|1|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|1|0.0%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Wed Jun 10 08:56:07 UTC 2015.

The ipset `blocklist_de_mail` has **19046** entries, **19046** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24120|35737|19046|53.2%|100.0%|
[blocklist_de](#blocklist_de)|30139|30139|19046|63.1%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|11059|74.5%|58.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2829|0.0%|14.8%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|2511|100.0%|13.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1394|0.0%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1260|0.0%|6.6%|
[nixspam](#nixspam)|39997|39997|876|2.1%|4.5%|
[firehol_level3](#firehol_level3)|109898|9627580|421|0.0%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|268|0.2%|1.4%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|163|1.5%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|148|0.5%|0.7%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|105|0.1%|0.5%|
[firehol_proxies](#firehol_proxies)|11912|12152|104|0.8%|0.5%|
[php_dictionary](#php_dictionary)|666|666|83|12.4%|0.4%|
[php_spammers](#php_spammers)|661|661|74|11.1%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|67|0.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|61|0.0%|0.3%|
[xroxy](#xroxy)|2148|2148|55|2.5%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|43|0.6%|0.2%|
[openbl_60d](#openbl_60d)|7028|7028|35|0.4%|0.1%|
[proxz](#proxz)|1191|1191|30|2.5%|0.1%|
[openbl_30d](#openbl_30d)|2854|2854|29|1.0%|0.1%|
[php_commenters](#php_commenters)|403|403|26|6.4%|0.1%|
[firehol_level1](#firehol_level1)|5146|688981376|23|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|23|13.1%|0.1%|
[et_block](#et_block)|999|18343755|22|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|22|0.7%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|21|0.0%|0.1%|
[openbl_7d](#openbl_7d)|697|697|7|1.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|6|1.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|4|0.1%|0.0%|
[shunlist](#shunlist)|1340|1340|3|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|3|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6449|6449|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6449|6449|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1438|1438|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|167|167|1|0.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[ciarmy](#ciarmy)|434|434|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Wed Jun 10 08:42:15 UTC 2015.

The ipset `blocklist_de_sip` has **80** entries, **80** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24120|35737|61|0.1%|76.2%|
[blocklist_de](#blocklist_de)|30139|30139|61|0.2%|76.2%|
[voipbl](#voipbl)|10522|10934|24|0.2%|30.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|21|0.0%|26.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13|0.0%|16.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|7.5%|
[firehol_level3](#firehol_level3)|109898|9627580|4|0.0%|5.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|2.5%|
[shunlist](#shunlist)|1340|1340|2|0.1%|2.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.5%|
[firehol_level1](#firehol_level1)|5146|688981376|2|0.0%|2.5%|
[et_block](#et_block)|999|18343755|2|0.0%|2.5%|
[et_botcc](#et_botcc)|509|509|1|0.1%|1.2%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Wed Jun 10 08:42:06 UTC 2015.

The ipset `blocklist_de_ssh` has **3304** entries, **3304** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24120|35737|3296|9.2%|99.7%|
[blocklist_de](#blocklist_de)|30139|30139|3295|10.9%|99.7%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|1147|0.6%|34.7%|
[firehol_level3](#firehol_level3)|109898|9627580|1034|0.0%|31.2%|
[openbl_60d](#openbl_60d)|7028|7028|960|13.6%|29.0%|
[openbl_30d](#openbl_30d)|2854|2854|769|26.9%|23.2%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|686|39.8%|20.7%|
[et_compromised](#et_compromised)|1718|1718|655|38.1%|19.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|486|0.0%|14.7%|
[shunlist](#shunlist)|1340|1340|419|31.2%|12.6%|
[openbl_7d](#openbl_7d)|697|697|385|55.2%|11.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|139|0.0%|4.2%|
[firehol_level1](#firehol_level1)|5146|688981376|131|0.0%|3.9%|
[openbl_1d](#openbl_1d)|167|167|124|74.2%|3.7%|
[et_block](#et_block)|999|18343755|124|0.0%|3.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|118|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|50|0.0%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|30|17.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|25|0.0%|0.7%|
[dshield](#dshield)|20|5120|11|0.2%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|7|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.1%|
[nixspam](#nixspam)|39997|39997|4|0.0%|0.1%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.0%|
[ciarmy](#ciarmy)|434|434|2|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|1|0.0%|0.0%|
[sslbl](#sslbl)|375|375|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|1|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6449|6449|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6449|6449|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Wed Jun 10 08:42:20 UTC 2015.

The ipset `blocklist_de_strongips` has **175** entries, **175** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24120|35737|175|0.4%|100.0%|
[blocklist_de](#blocklist_de)|30139|30139|175|0.5%|100.0%|
[firehol_level3](#firehol_level3)|109898|9627580|156|0.0%|89.1%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|130|0.1%|74.2%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|129|4.2%|73.7%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|116|0.3%|66.2%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|107|1.5%|61.1%|
[php_commenters](#php_commenters)|403|403|45|11.1%|25.7%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|35|0.0%|20.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|33|0.2%|18.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|30|0.9%|17.1%|
[openbl_60d](#openbl_60d)|7028|7028|25|0.3%|14.2%|
[openbl_7d](#openbl_7d)|697|697|24|3.4%|13.7%|
[openbl_30d](#openbl_30d)|2854|2854|24|0.8%|13.7%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|23|0.1%|13.1%|
[openbl_1d](#openbl_1d)|167|167|22|13.1%|12.5%|
[shunlist](#shunlist)|1340|1340|19|1.4%|10.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|9.1%|
[firehol_level1](#firehol_level1)|5146|688981376|13|0.0%|7.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8|0.0%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|4.5%|
[et_block](#et_block)|999|18343755|8|0.0%|4.5%|
[php_spammers](#php_spammers)|661|661|7|1.0%|4.0%|
[firehol_proxies](#firehol_proxies)|11912|12152|7|0.0%|4.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|7|0.0%|4.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|7|0.2%|4.0%|
[xroxy](#xroxy)|2148|2148|6|0.2%|3.4%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|6|0.0%|3.4%|
[proxyrss](#proxyrss)|1438|1438|6|0.4%|3.4%|
[proxz](#proxz)|1191|1191|5|0.4%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|2.2%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|2.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|2|0.0%|1.1%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|1.1%|
[dshield](#dshield)|20|5120|2|0.0%|1.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|2|0.2%|1.1%|
[nixspam](#nixspam)|39997|39997|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Wed Jun 10 09:00:03 UTC 2015.

The ipset `bm_tor` has **6449** entries, **6449** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18393|82416|6449|7.8%|100.0%|
[dm_tor](#dm_tor)|6449|6449|6369|98.7%|98.7%|
[et_tor](#et_tor)|6340|6340|5687|89.7%|88.1%|
[firehol_level3](#firehol_level3)|109898|9627580|1101|0.0%|17.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1063|10.3%|16.4%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|635|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|621|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|527|1.7%|8.1%|
[firehol_level2](#firehol_level2)|24120|35737|366|1.0%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|362|5.2%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|182|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11912|12152|166|1.3%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|164|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|162|43.5%|2.5%|
[php_commenters](#php_commenters)|403|403|48|11.9%|0.7%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|40|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7028|7028|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|30139|30139|10|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|9|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.1%|
[et_block](#et_block)|999|18343755|7|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|7|0.2%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|4|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981376|3|0.0%|0.0%|
[nixspam](#nixspam)|39997|39997|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|2|0.0%|0.0%|
[xroxy](#xroxy)|2148|2148|1|0.0%|0.0%|
[shunlist](#shunlist)|1340|1340|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109898|9627580|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|434|434|1|0.2%|0.0%|
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
[firehol_level3](#firehol_level3)|109898|9627580|1720|0.0%|100.0%|
[et_compromised](#et_compromised)|1718|1718|1661|96.6%|96.5%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|1110|0.6%|64.5%|
[openbl_60d](#openbl_60d)|7028|7028|1003|14.2%|58.3%|
[openbl_30d](#openbl_30d)|2854|2854|942|33.0%|54.7%|
[firehol_level2](#firehol_level2)|24120|35737|691|1.9%|40.1%|
[blocklist_de](#blocklist_de)|30139|30139|689|2.2%|40.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|686|20.7%|39.8%|
[shunlist](#shunlist)|1340|1340|450|33.5%|26.1%|
[openbl_7d](#openbl_7d)|697|697|327|46.9%|19.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|152|0.0%|8.8%|
[firehol_level1](#firehol_level1)|5146|688981376|102|0.0%|5.9%|
[et_block](#et_block)|999|18343755|98|0.0%|5.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|95|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|86|0.0%|5.0%|
[openbl_1d](#openbl_1d)|167|167|64|38.3%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|13|0.0%|0.7%|
[dshield](#dshield)|20|5120|6|0.1%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|11912|12152|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|3|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|3|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|3|0.1%|0.1%|
[proxz](#proxz)|1191|1191|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[ciarmy](#ciarmy)|434|434|2|0.4%|0.1%|
[xroxy](#xroxy)|2148|2148|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1438|1438|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Wed Jun 10 07:15:13 UTC 2015.

The ipset `ciarmy` has **434** entries, **434** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109898|9627580|434|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|417|0.2%|96.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|95|0.0%|21.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|47|0.0%|10.8%|
[firehol_level2](#firehol_level2)|24120|35737|41|0.1%|9.4%|
[blocklist_de](#blocklist_de)|30139|30139|40|0.1%|9.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|8.2%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|35|0.2%|8.0%|
[shunlist](#shunlist)|1340|1340|29|2.1%|6.6%|
[firehol_level1](#firehol_level1)|5146|688981376|5|0.0%|1.1%|
[et_block](#et_block)|999|18343755|4|0.0%|0.9%|
[dshield](#dshield)|20|5120|4|0.0%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2|0.0%|0.4%|
[openbl_7d](#openbl_7d)|697|697|2|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7028|7028|2|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2854|2854|2|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|2|0.1%|0.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|2|0.0%|0.4%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|2|0.2%|0.4%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|167|167|1|0.5%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|1|0.0%|0.2%|

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
[firehol_level3](#firehol_level3)|109898|9627580|123|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|13.0%|
[malc0de](#malc0de)|338|338|13|3.8%|10.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|3|0.0%|2.4%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|2|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|1.6%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.8%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Wed Jun 10 08:45:04 UTC 2015.

The ipset `dm_tor` has **6449** entries, **6449** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18393|82416|6449|7.8%|100.0%|
[bm_tor](#bm_tor)|6449|6449|6369|98.7%|98.7%|
[et_tor](#et_tor)|6340|6340|5665|89.3%|87.8%|
[firehol_level3](#firehol_level3)|109898|9627580|1099|0.0%|17.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1061|10.3%|16.4%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|633|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|618|0.0%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|525|1.7%|8.1%|
[firehol_level2](#firehol_level2)|24120|35737|364|1.0%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|360|5.1%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|183|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11912|12152|167|1.3%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|164|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|163|43.8%|2.5%|
[php_commenters](#php_commenters)|403|403|48|11.9%|0.7%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|41|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7028|7028|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|30139|30139|10|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|9|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.1%|
[et_block](#et_block)|999|18343755|7|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|7|0.2%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|4|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981376|3|0.0%|0.0%|
[nixspam](#nixspam)|39997|39997|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|2|0.0%|0.0%|
[xroxy](#xroxy)|2148|2148|1|0.0%|0.0%|
[shunlist](#shunlist)|1340|1340|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Wed Jun 10 07:58:43 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5146|688981376|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|2052|1.1%|40.0%|
[et_block](#et_block)|999|18343755|1024|0.0%|20.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|256|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7028|7028|50|0.7%|0.9%|
[firehol_level3](#firehol_level3)|109898|9627580|48|0.0%|0.9%|
[openbl_30d](#openbl_30d)|2854|2854|37|1.2%|0.7%|
[shunlist](#shunlist)|1340|1340|25|1.8%|0.4%|
[firehol_level2](#firehol_level2)|24120|35737|15|0.0%|0.2%|
[blocklist_de](#blocklist_de)|30139|30139|15|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|11|0.3%|0.2%|
[et_compromised](#et_compromised)|1718|1718|6|0.3%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|6|0.3%|0.1%|
[openbl_7d](#openbl_7d)|697|697|5|0.7%|0.0%|
[ciarmy](#ciarmy)|434|434|4|0.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|4|0.0%|0.0%|
[openbl_1d](#openbl_1d)|167|167|3|1.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|2|1.1%|0.0%|
[malc0de](#malc0de)|338|338|1|0.2%|0.0%|

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
[firehol_level3](#firehol_level3)|109898|9627580|6933346|72.0%|37.7%|
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
[firehol_level2](#firehol_level2)|24120|35737|285|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7028|7028|247|3.5%|0.0%|
[zeus](#zeus)|231|231|228|98.7%|0.0%|
[blocklist_de](#blocklist_de)|30139|30139|212|0.7%|0.0%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|128|4.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|124|3.7%|0.0%|
[shunlist](#shunlist)|1340|1340|111|8.2%|0.0%|
[et_compromised](#et_compromised)|1718|1718|103|5.9%|0.0%|
[feodo](#feodo)|104|104|102|98.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|98|5.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|89|1.2%|0.0%|
[nixspam](#nixspam)|39997|39997|82|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|56|1.8%|0.0%|
[openbl_7d](#openbl_7d)|697|697|53|7.6%|0.0%|
[sslbl](#sslbl)|375|375|38|10.1%|0.0%|
[php_commenters](#php_commenters)|403|403|30|7.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|22|0.1%|0.0%|
[voipbl](#voipbl)|10522|10934|18|0.1%|0.0%|
[openbl_1d](#openbl_1d)|167|167|17|10.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|13|0.5%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|11|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|8|0.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|8|4.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|8|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|7|0.1%|0.0%|
[dm_tor](#dm_tor)|6449|6449|7|0.1%|0.0%|
[bm_tor](#bm_tor)|6449|6449|7|0.1%|0.0%|
[php_dictionary](#php_dictionary)|666|666|6|0.9%|0.0%|
[malc0de](#malc0de)|338|338|5|1.4%|0.0%|
[firehol_proxies](#firehol_proxies)|11912|12152|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|5|0.1%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[ciarmy](#ciarmy)|434|434|4|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_botcc](#et_botcc)|509|509|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|2|2.5%|0.0%|
[xroxy](#xroxy)|2148|2148|1|0.0%|0.0%|
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
[firehol_level3](#firehol_level3)|109898|9627580|3|0.0%|0.5%|
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
[firehol_level3](#firehol_level3)|109898|9627580|1683|0.0%|97.9%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1661|96.5%|96.6%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|1109|0.6%|64.5%|
[openbl_60d](#openbl_60d)|7028|7028|1004|14.2%|58.4%|
[openbl_30d](#openbl_30d)|2854|2854|937|32.8%|54.5%|
[firehol_level2](#firehol_level2)|24120|35737|660|1.8%|38.4%|
[blocklist_de](#blocklist_de)|30139|30139|658|2.1%|38.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|655|19.8%|38.1%|
[shunlist](#shunlist)|1340|1340|451|33.6%|26.2%|
[openbl_7d](#openbl_7d)|697|697|318|45.6%|18.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|153|0.0%|8.9%|
[firehol_level1](#firehol_level1)|5146|688981376|107|0.0%|6.2%|
[et_block](#et_block)|999|18343755|103|0.0%|5.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|101|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|89|0.0%|5.1%|
[openbl_1d](#openbl_1d)|167|167|58|34.7%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|13|0.0%|0.7%|
[dshield](#dshield)|20|5120|6|0.1%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11912|12152|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|3|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|3|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|3|0.1%|0.1%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.1%|
[proxz](#proxz)|1191|1191|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2148|2148|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1438|1438|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[ciarmy](#ciarmy)|434|434|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|1|0.0%|0.0%|

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
[firehol_anonymous](#firehol_anonymous)|18393|82416|5701|6.9%|89.9%|
[bm_tor](#bm_tor)|6449|6449|5687|88.1%|89.7%|
[dm_tor](#dm_tor)|6449|6449|5665|87.8%|89.3%|
[firehol_level3](#firehol_level3)|109898|9627580|1105|0.0%|17.4%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1068|10.4%|16.8%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|642|0.6%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|614|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|533|1.8%|8.4%|
[firehol_level2](#firehol_level2)|24120|35737|367|1.0%|5.7%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|363|5.2%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|183|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11912|12152|166|1.3%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|163|43.8%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|163|0.0%|2.5%|
[php_commenters](#php_commenters)|403|403|48|11.9%|0.7%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|39|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7028|7028|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|30139|30139|10|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|9|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|8|0.2%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.1%|
[et_block](#et_block)|999|18343755|7|0.0%|0.1%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981376|3|0.0%|0.0%|
[nixspam](#nixspam)|39997|39997|2|0.0%|0.0%|
[xroxy](#xroxy)|2148|2148|1|0.0%|0.0%|
[shunlist](#shunlist)|1340|1340|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun 10 09:00:26 UTC 2015.

The ipset `feodo` has **104** entries, **104** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5146|688981376|104|0.0%|100.0%|
[et_block](#et_block)|999|18343755|102|0.0%|98.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|82|0.7%|78.8%|
[firehol_level3](#firehol_level3)|109898|9627580|82|0.0%|78.8%|
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

The ipset `firehol_anonymous` has **18393** entries, **82416** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11912|12152|12152|100.0%|14.7%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|7484|100.0%|9.0%|
[firehol_level3](#firehol_level3)|109898|9627580|6473|0.0%|7.8%|
[dm_tor](#dm_tor)|6449|6449|6449|100.0%|7.8%|
[bm_tor](#bm_tor)|6449|6449|6449|100.0%|7.8%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|5939|6.3%|7.2%|
[et_tor](#et_tor)|6340|6340|5701|89.9%|6.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3426|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2884|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2845|0.0%|3.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2740|9.3%|3.3%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|2703|100.0%|3.2%|
[xroxy](#xroxy)|2148|2148|2148|100.0%|2.6%|
[proxyrss](#proxyrss)|1438|1438|1438|100.0%|1.7%|
[firehol_level2](#firehol_level2)|24120|35737|1343|3.7%|1.6%|
[proxz](#proxz)|1191|1191|1191|100.0%|1.4%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1163|11.3%|1.4%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|1013|14.5%|1.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.8%|
[blocklist_de](#blocklist_de)|30139|30139|624|2.0%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|504|16.7%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|105|0.5%|0.1%|
[nixspam](#nixspam)|39997|39997|90|0.2%|0.1%|
[php_dictionary](#php_dictionary)|666|666|89|13.3%|0.1%|
[voipbl](#voipbl)|10522|10934|78|0.7%|0.0%|
[php_spammers](#php_spammers)|661|661|76|11.4%|0.0%|
[php_commenters](#php_commenters)|403|403|76|18.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|56|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|28|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7028|7028|23|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|15|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|13|0.3%|0.0%|
[php_harvesters](#php_harvesters)|378|378|12|3.1%|0.0%|
[et_block](#et_block)|999|18343755|11|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981376|7|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|7|4.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1718|1718|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|3|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|2|0.0%|0.0%|
[sslbl](#sslbl)|375|375|1|0.2%|0.0%|
[shunlist](#shunlist)|1340|1340|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|1|0.1%|0.0%|

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
[firehol_level3](#firehol_level3)|109898|9627580|7500204|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7498240|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4638626|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2569506|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|3566|1.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1932|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1102|1.1%|0.0%|
[sslbl](#sslbl)|375|375|375|100.0%|0.0%|
[voipbl](#voipbl)|10522|10934|333|3.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|302|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|300|2.9%|0.0%|
[firehol_level2](#firehol_level2)|24120|35737|296|0.8%|0.0%|
[openbl_60d](#openbl_60d)|7028|7028|288|4.0%|0.0%|
[zeus](#zeus)|231|231|231|100.0%|0.0%|
[blocklist_de](#blocklist_de)|30139|30139|225|0.7%|0.0%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|0.0%|
[shunlist](#shunlist)|1340|1340|187|13.9%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|159|5.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|131|3.9%|0.0%|
[et_compromised](#et_compromised)|1718|1718|107|6.2%|0.0%|
[feodo](#feodo)|104|104|104|100.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|102|5.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|89|1.2%|0.0%|
[nixspam](#nixspam)|39997|39997|84|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|60|1.9%|0.0%|
[openbl_7d](#openbl_7d)|697|697|54|7.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|39|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[php_commenters](#php_commenters)|403|403|37|9.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|23|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[openbl_1d](#openbl_1d)|167|167|17|10.1%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|13|7.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|13|0.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|9|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|6|0.9%|0.0%|
[malc0de](#malc0de)|338|338|6|1.7%|0.0%|
[ciarmy](#ciarmy)|434|434|5|1.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|5|0.1%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11912|12152|3|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6449|6449|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6449|6449|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|2|2.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **24120** entries, **35737** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|30139|30139|30139|100.0%|84.3%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|19046|100.0%|53.2%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|14825|100.0%|41.4%|
[firehol_level3](#firehol_level3)|109898|9627580|7365|0.0%|20.6%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|6941|100.0%|19.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|6779|23.1%|18.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|6004|6.3%|16.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4304|0.0%|12.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|3466|99.9%|9.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|3296|99.7%|9.2%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|3012|100.0%|8.4%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|2511|100.0%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1762|0.0%|4.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1659|0.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|1444|0.7%|4.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|1343|1.6%|3.7%|
[firehol_proxies](#firehol_proxies)|11912|12152|1117|9.1%|3.1%|
[openbl_60d](#openbl_60d)|7028|7028|1060|15.0%|2.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|941|99.8%|2.6%|
[nixspam](#nixspam)|39997|39997|928|2.3%|2.5%|
[openbl_30d](#openbl_30d)|2854|2854|842|29.5%|2.3%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|691|40.1%|1.9%|
[et_compromised](#et_compromised)|1718|1718|660|38.4%|1.8%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|654|8.7%|1.8%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|577|5.6%|1.6%|
[shunlist](#shunlist)|1340|1340|465|34.7%|1.3%|
[openbl_7d](#openbl_7d)|697|697|433|62.1%|1.2%|
[proxyrss](#proxyrss)|1438|1438|415|28.8%|1.1%|
[et_tor](#et_tor)|6340|6340|367|5.7%|1.0%|
[bm_tor](#bm_tor)|6449|6449|366|5.6%|1.0%|
[dm_tor](#dm_tor)|6449|6449|364|5.6%|1.0%|
[xroxy](#xroxy)|2148|2148|328|15.2%|0.9%|
[firehol_level1](#firehol_level1)|5146|688981376|296|0.0%|0.8%|
[et_block](#et_block)|999|18343755|285|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|272|0.0%|0.7%|
[proxz](#proxz)|1191|1191|256|21.4%|0.7%|
[php_commenters](#php_commenters)|403|403|184|45.6%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|175|100.0%|0.4%|
[openbl_1d](#openbl_1d)|167|167|167|100.0%|0.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|156|41.9%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|149|5.5%|0.4%|
[php_dictionary](#php_dictionary)|666|666|108|16.2%|0.3%|
[php_spammers](#php_spammers)|661|661|105|15.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|94|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|61|76.2%|0.1%|
[php_harvesters](#php_harvesters)|378|378|58|15.3%|0.1%|
[ciarmy](#ciarmy)|434|434|41|9.4%|0.1%|
[voipbl](#voipbl)|10522|10934|30|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|16|0.0%|0.0%|
[dshield](#dshield)|20|5120|15|0.2%|0.0%|
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

The ipset `firehol_level3` has **109898** entries, **9627580** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5146|688981376|7500204|1.0%|77.9%|
[et_block](#et_block)|999|18343755|6933346|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6933035|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537321|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919972|0.1%|9.5%|
[fullbogons](#fullbogons)|3778|670299624|566693|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161589|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|93938|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|28011|95.4%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|10254|100.0%|0.1%|
[firehol_level2](#firehol_level2)|24120|35737|7365|20.6%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|6473|7.8%|0.0%|
[firehol_proxies](#firehol_proxies)|11912|12152|5357|44.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|5208|2.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|4674|67.3%|0.0%|
[blocklist_de](#blocklist_de)|30139|30139|3828|12.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|3593|48.0%|0.0%|
[openbl_60d](#openbl_60d)|7028|7028|2986|42.4%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|2854|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|2200|73.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1720|100.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1683|97.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|1528|56.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[shunlist](#shunlist)|1340|1340|1340|100.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[xroxy](#xroxy)|2148|2148|1286|59.8%|0.0%|
[et_tor](#et_tor)|6340|6340|1105|17.4%|0.0%|
[bm_tor](#bm_tor)|6449|6449|1101|17.0%|0.0%|
[dm_tor](#dm_tor)|6449|6449|1099|17.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|1034|31.2%|0.0%|
[nixspam](#nixspam)|39997|39997|871|2.1%|0.0%|
[proxz](#proxz)|1191|1191|712|59.7%|0.0%|
[openbl_7d](#openbl_7d)|697|697|697|100.0%|0.0%|
[proxyrss](#proxyrss)|1438|1438|680|47.2%|0.0%|
[php_dictionary](#php_dictionary)|666|666|666|100.0%|0.0%|
[php_spammers](#php_spammers)|661|661|661|100.0%|0.0%|
[ciarmy](#ciarmy)|434|434|434|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|421|2.2%|0.0%|
[php_commenters](#php_commenters)|403|403|403|100.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|378|100.0%|0.0%|
[malc0de](#malc0de)|338|338|338|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|310|2.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|234|62.9%|0.0%|
[zeus](#zeus)|231|231|204|88.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|181|89.1%|0.0%|
[openbl_1d](#openbl_1d)|167|167|166|99.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|156|89.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|123|100.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|97|2.7%|0.0%|
[sslbl](#sslbl)|375|375|96|25.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|89|0.0%|0.0%|
[feodo](#feodo)|104|104|82|78.8%|0.0%|
[voipbl](#voipbl)|10522|10934|59|0.5%|0.0%|
[dshield](#dshield)|20|5120|48|0.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|45|1.7%|0.0%|
[virbl](#virbl)|27|27|27|100.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|23|3.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|21|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|17|1.8%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
[bogons](#bogons)|13|592708608|4|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|4|5.0%|0.0%|
[et_botcc](#et_botcc)|509|509|3|0.5%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **11912** entries, **12152** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18393|82416|12152|14.7%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|7484|100.0%|61.5%|
[firehol_level3](#firehol_level3)|109898|9627580|5357|0.0%|44.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|5295|5.6%|43.5%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|2703|100.0%|22.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2332|7.9%|19.1%|
[xroxy](#xroxy)|2148|2148|2148|100.0%|17.6%|
[proxyrss](#proxyrss)|1438|1438|1438|100.0%|11.8%|
[proxz](#proxz)|1191|1191|1191|100.0%|9.8%|
[firehol_level2](#firehol_level2)|24120|35737|1117|3.1%|9.1%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|793|11.4%|6.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.4%|
[blocklist_de](#blocklist_de)|30139|30139|613|2.0%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|503|16.6%|4.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|497|0.0%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|381|0.0%|3.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|280|0.0%|2.3%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|254|2.4%|2.0%|
[dm_tor](#dm_tor)|6449|6449|167|2.5%|1.3%|
[et_tor](#et_tor)|6340|6340|166|2.6%|1.3%|
[bm_tor](#bm_tor)|6449|6449|166|2.5%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|104|0.5%|0.8%|
[php_dictionary](#php_dictionary)|666|666|88|13.2%|0.7%|
[nixspam](#nixspam)|39997|39997|88|0.2%|0.7%|
[php_spammers](#php_spammers)|661|661|74|11.1%|0.6%|
[php_commenters](#php_commenters)|403|403|69|17.1%|0.5%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|35|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7028|7028|18|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|11|2.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|7|4.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|7|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|6|0.1%|0.0%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981376|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|3|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|2|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.0%|
[sslbl](#sslbl)|375|375|1|0.2%|0.0%|
[shunlist](#shunlist)|1340|1340|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109898|9627580|566693|5.8%|0.0%|
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
[ciarmy](#ciarmy)|434|434|1|0.2%|0.0%|
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
[firehol_level3](#firehol_level3)|109898|9627580|21|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5146|688981376|18|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11912|12152|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|15|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|13|0.0%|0.0%|
[fullbogons](#fullbogons)|3778|670299624|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[et_block](#et_block)|999|18343755|11|0.0%|0.0%|
[firehol_level2](#firehol_level2)|24120|35737|10|0.0%|0.0%|
[blocklist_de](#blocklist_de)|30139|30139|8|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[nixspam](#nixspam)|39997|39997|5|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|5|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|4|0.0%|0.0%|
[xroxy](#xroxy)|2148|2148|3|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[proxz](#proxz)|1191|1191|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|1|0.0%|0.0%|
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
[firehol_level3](#firehol_level3)|109898|9627580|9177856|95.3%|100.0%|
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
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|167|0.5%|0.0%|
[firehol_level2](#firehol_level2)|24120|35737|94|0.2%|0.0%|
[nixspam](#nixspam)|39997|39997|82|0.2%|0.0%|
[blocklist_de](#blocklist_de)|30139|30139|61|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|53|1.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|38|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|7028|7028|16|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[zeus](#zeus)|231|231|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|7|0.0%|0.0%|
[openbl_7d](#openbl_7d)|697|697|5|0.7%|0.0%|
[et_compromised](#et_compromised)|1718|1718|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|5|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|5|0.1%|0.0%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|0.0%|
[et_tor](#et_tor)|6340|6340|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6449|6449|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6449|6449|4|0.0%|0.0%|
[shunlist](#shunlist)|1340|1340|3|0.2%|0.0%|
[php_spammers](#php_spammers)|661|661|3|0.4%|0.0%|
[openbl_1d](#openbl_1d)|167|167|3|1.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|3|1.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11912|12152|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|2|0.0%|0.0%|
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
[firehol_level1](#firehol_level1)|5146|688981376|2569506|0.3%|0.3%|
[et_block](#et_block)|999|18343755|2272798|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|109898|9627580|919972|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3778|670299624|263817|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|4218|2.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|3426|4.1%|0.0%|
[firehol_level2](#firehol_level2)|24120|35737|1659|4.6%|0.0%|
[blocklist_de](#blocklist_de)|30139|30139|1540|5.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1519|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|1394|7.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|1333|8.9%|0.0%|
[nixspam](#nixspam)|39997|39997|978|2.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|529|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[voipbl](#voipbl)|10522|10934|299|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11912|12152|280|2.3%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[dm_tor](#dm_tor)|6449|6449|164|2.5%|0.0%|
[bm_tor](#bm_tor)|6449|6449|164|2.5%|0.0%|
[openbl_60d](#openbl_60d)|7028|7028|163|2.3%|0.0%|
[et_tor](#et_tor)|6340|6340|163|2.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|152|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|134|1.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|118|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|83|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|64|2.2%|0.0%|
[xroxy](#xroxy)|2148|2148|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[et_compromised](#et_compromised)|1718|1718|52|3.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|52|3.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|50|1.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|42|1.2%|0.0%|
[proxz](#proxz)|1191|1191|41|3.4%|0.0%|
[et_botcc](#et_botcc)|509|509|39|7.6%|0.0%|
[ciarmy](#ciarmy)|434|434|36|8.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|32|1.0%|0.0%|
[proxyrss](#proxyrss)|1438|1438|28|1.9%|0.0%|
[shunlist](#shunlist)|1340|1340|27|2.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|24|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[openbl_7d](#openbl_7d)|697|697|13|1.8%|0.0%|
[php_dictionary](#php_dictionary)|666|666|12|1.8%|0.0%|
[php_harvesters](#php_harvesters)|378|378|11|2.9%|0.0%|
[malc0de](#malc0de)|338|338|11|3.2%|0.0%|
[php_spammers](#php_spammers)|661|661|10|1.5%|0.0%|
[php_commenters](#php_commenters)|403|403|10|2.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|8|0.8%|0.0%|
[zeus](#zeus)|231|231|7|3.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|6|7.5%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|4|1.9%|0.0%|
[sslbl](#sslbl)|375|375|3|0.8%|0.0%|
[feodo](#feodo)|104|104|3|2.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|3|2.4%|0.0%|
[virbl](#virbl)|27|27|2|7.4%|0.0%|
[openbl_1d](#openbl_1d)|167|167|2|1.1%|0.0%|

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
[firehol_level3](#firehol_level3)|109898|9627580|2537321|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3778|670299624|252159|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|6261|3.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|2884|3.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2502|2.6%|0.0%|
[firehol_level2](#firehol_level2)|24120|35737|1762|4.9%|0.0%|
[blocklist_de](#blocklist_de)|30139|30139|1596|5.2%|0.0%|
[nixspam](#nixspam)|39997|39997|1397|3.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|1260|6.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|1104|7.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|790|2.6%|0.0%|
[voipbl](#voipbl)|10522|10934|434|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|11912|12152|381|3.1%|0.0%|
[openbl_60d](#openbl_60d)|7028|7028|320|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|219|2.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|212|3.0%|0.0%|
[et_tor](#et_tor)|6340|6340|183|2.8%|0.0%|
[dm_tor](#dm_tor)|6449|6449|183|2.8%|0.0%|
[bm_tor](#bm_tor)|6449|6449|182|2.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|164|1.5%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|148|5.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|139|4.2%|0.0%|
[xroxy](#xroxy)|2148|2148|104|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|103|3.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|97|3.2%|0.0%|
[et_compromised](#et_compromised)|1718|1718|89|5.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|86|5.0%|0.0%|
[shunlist](#shunlist)|1340|1340|77|5.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|69|1.9%|0.0%|
[proxyrss](#proxyrss)|1438|1438|57|3.9%|0.0%|
[php_spammers](#php_spammers)|661|661|52|7.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|50|1.9%|0.0%|
[proxz](#proxz)|1191|1191|49|4.1%|0.0%|
[ciarmy](#ciarmy)|434|434|47|10.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[openbl_7d](#openbl_7d)|697|697|42|6.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[php_dictionary](#php_dictionary)|666|666|22|3.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[et_botcc](#et_botcc)|509|509|21|4.1%|0.0%|
[malc0de](#malc0de)|338|338|19|5.6%|0.0%|
[php_commenters](#php_commenters)|403|403|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|16|1.6%|0.0%|
[zeus](#zeus)|231|231|9|3.8%|0.0%|
[php_harvesters](#php_harvesters)|378|378|9|2.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|8|3.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|8|4.5%|0.0%|
[sslbl](#sslbl)|375|375|6|1.6%|0.0%|
[openbl_1d](#openbl_1d)|167|167|6|3.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|6|7.5%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|104|104|3|2.8%|0.0%|
[virbl](#virbl)|27|27|2|7.4%|0.0%|
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
[firehol_level1](#firehol_level1)|5146|688981376|4638626|0.6%|3.3%|
[fullbogons](#fullbogons)|3778|670299624|4237167|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|109898|9627580|161589|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|999|18343755|130922|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|13623|7.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|5824|6.1%|0.0%|
[firehol_level2](#firehol_level2)|24120|35737|4304|12.0%|0.0%|
[blocklist_de](#blocklist_de)|30139|30139|3902|12.9%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|2845|3.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|2829|14.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|2343|15.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1913|6.5%|0.0%|
[nixspam](#nixspam)|39997|39997|1614|4.0%|0.0%|
[voipbl](#voipbl)|10522|10934|1602|14.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7028|7028|747|10.6%|0.0%|
[bm_tor](#bm_tor)|6449|6449|621|9.6%|0.0%|
[dm_tor](#dm_tor)|6449|6449|618|9.5%|0.0%|
[et_tor](#et_tor)|6340|6340|614|9.6%|0.0%|
[firehol_proxies](#firehol_proxies)|11912|12152|497|4.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|486|14.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|472|6.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|318|12.6%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|295|10.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|256|2.4%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|252|7.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|214|2.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|177|5.8%|0.0%|
[et_compromised](#et_compromised)|1718|1718|153|8.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|152|8.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|125|13.2%|0.0%|
[shunlist](#shunlist)|1340|1340|121|9.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[xroxy](#xroxy)|2148|2148|107|4.9%|0.0%|
[proxz](#proxz)|1191|1191|99|8.3%|0.0%|
[ciarmy](#ciarmy)|434|434|95|21.8%|0.0%|
[openbl_7d](#openbl_7d)|697|697|79|11.3%|0.0%|
[et_botcc](#et_botcc)|509|509|77|15.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|57|2.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[proxyrss](#proxyrss)|1438|1438|46|3.1%|0.0%|
[malc0de](#malc0de)|338|338|46|13.6%|0.0%|
[php_spammers](#php_spammers)|661|661|41|6.2%|0.0%|
[php_dictionary](#php_dictionary)|666|666|35|5.2%|0.0%|
[sslbl](#sslbl)|375|375|28|7.4%|0.0%|
[php_commenters](#php_commenters)|403|403|25|6.2%|0.0%|
[php_harvesters](#php_harvesters)|378|378|20|5.2%|0.0%|
[openbl_1d](#openbl_1d)|167|167|19|11.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|16|13.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|16|9.1%|0.0%|
[zeus](#zeus)|231|231|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|13|16.2%|0.0%|
[feodo](#feodo)|104|104|11|10.5%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[virbl](#virbl)|27|27|4|14.8%|0.0%|
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
[firehol_proxies](#firehol_proxies)|11912|12152|663|5.4%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|663|0.8%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|109898|9627580|23|0.0%|3.4%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|18|0.0%|2.7%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|14|0.1%|2.1%|
[xroxy](#xroxy)|2148|2148|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1438|1438|10|0.6%|1.5%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|7|0.2%|1.0%|
[proxz](#proxz)|1191|1191|6|0.5%|0.9%|
[firehol_level2](#firehol_level2)|24120|35737|6|0.0%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|5|0.0%|0.7%|
[blocklist_de](#blocklist_de)|30139|30139|4|0.0%|0.6%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5146|688981376|2|0.0%|0.3%|
[et_block](#et_block)|999|18343755|2|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|666|666|1|0.1%|0.1%|
[nixspam](#nixspam)|39997|39997|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|1|0.0%|0.1%|
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
[firehol_level3](#firehol_level3)|109898|9627580|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5146|688981376|1932|0.0%|0.5%|
[et_block](#et_block)|999|18343755|1043|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3778|670299624|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|289|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|48|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|28|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[et_tor](#et_tor)|6340|6340|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6449|6449|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6449|6449|22|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|18|0.0%|0.0%|
[firehol_level2](#firehol_level2)|24120|35737|16|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|14|0.1%|0.0%|
[nixspam](#nixspam)|39997|39997|12|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11912|12152|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|10|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|6|0.0%|0.0%|
[blocklist_de](#blocklist_de)|30139|30139|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7028|7028|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10522|10934|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|3|0.1%|0.0%|
[malc0de](#malc0de)|338|338|3|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[et_compromised](#et_compromised)|1718|1718|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|2|2.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[xroxy](#xroxy)|2148|2148|1|0.0%|0.0%|
[sslbl](#sslbl)|375|375|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|1|0.0%|0.0%|
[proxz](#proxz)|1191|1191|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1438|1438|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|666|666|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[feodo](#feodo)|104|104|1|0.9%|0.0%|
[ciarmy](#ciarmy)|434|434|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109898|9627580|1450|0.0%|100.0%|
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
[firehol_proxies](#firehol_proxies)|11912|12152|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7028|7028|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2854|2854|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[firehol_level2](#firehol_level2)|24120|35737|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|697|697|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|30139|30139|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109898|9627580|338|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|46|0.0%|13.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|19|0.0%|5.6%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|13|10.5%|3.8%|
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
[firehol_level3](#firehol_level3)|109898|9627580|1288|0.0%|100.0%|
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
[cleanmx_viruses](#cleanmx_viruses)|123|123|1|0.8%|0.0%|

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
[firehol_proxies](#firehol_proxies)|11912|12152|372|3.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|372|0.4%|100.0%|
[firehol_level3](#firehol_level3)|109898|9627580|234|0.0%|62.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|233|0.2%|62.6%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|192|0.6%|51.6%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|170|1.6%|45.6%|
[et_tor](#et_tor)|6340|6340|163|2.5%|43.8%|
[dm_tor](#dm_tor)|6449|6449|163|2.5%|43.8%|
[bm_tor](#bm_tor)|6449|6449|162|2.5%|43.5%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|156|2.2%|41.9%|
[firehol_level2](#firehol_level2)|24120|35737|156|0.4%|41.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|125|0.0%|33.6%|
[php_commenters](#php_commenters)|403|403|44|10.9%|11.8%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7028|7028|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|378|378|6|1.5%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|4|0.0%|1.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|1.0%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|1.0%|
[et_block](#et_block)|999|18343755|2|0.0%|0.5%|
[xroxy](#xroxy)|2148|2148|1|0.0%|0.2%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.2%|
[shunlist](#shunlist)|1340|1340|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|30139|30139|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Wed Jun 10 09:00:02 UTC 2015.

The ipset `nixspam` has **39997** entries, **39997** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1614|0.0%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1397|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|978|0.0%|2.4%|
[firehol_level2](#firehol_level2)|24120|35737|928|2.5%|2.3%|
[blocklist_de](#blocklist_de)|30139|30139|924|3.0%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|876|4.5%|2.1%|
[firehol_level3](#firehol_level3)|109898|9627580|871|0.0%|2.1%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|625|6.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|132|0.1%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|90|0.1%|0.2%|
[firehol_proxies](#firehol_proxies)|11912|12152|88|0.7%|0.2%|
[firehol_level1](#firehol_level1)|5146|688981376|84|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|82|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|82|0.0%|0.2%|
[et_block](#et_block)|999|18343755|82|0.0%|0.2%|
[php_dictionary](#php_dictionary)|666|666|74|11.1%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|66|0.2%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|62|0.8%|0.1%|
[php_spammers](#php_spammers)|661|661|59|8.9%|0.1%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|46|0.0%|0.1%|
[xroxy](#xroxy)|2148|2148|39|1.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|24|0.3%|0.0%|
[proxz](#proxz)|1191|1191|21|1.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|18|0.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|18|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|17|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|17|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|12|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|9|2.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|9|0.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|7|0.2%|0.0%|
[proxyrss](#proxyrss)|1438|1438|6|0.4%|0.0%|
[php_commenters](#php_commenters)|403|403|5|1.2%|0.0%|
[openbl_60d](#openbl_60d)|7028|7028|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|4|0.1%|0.0%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|2|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6449|6449|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6449|6449|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|1|0.5%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Wed Jun 10 08:32:00 UTC 2015.

The ipset `openbl_1d` has **167** entries, **167** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24120|35737|167|0.4%|100.0%|
[openbl_7d](#openbl_7d)|697|697|166|23.8%|99.4%|
[openbl_60d](#openbl_60d)|7028|7028|166|2.3%|99.4%|
[openbl_30d](#openbl_30d)|2854|2854|166|5.8%|99.4%|
[firehol_level3](#firehol_level3)|109898|9627580|166|0.0%|99.4%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|157|0.0%|94.0%|
[blocklist_de](#blocklist_de)|30139|30139|126|0.4%|75.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|124|3.7%|74.2%|
[shunlist](#shunlist)|1340|1340|67|5.0%|40.1%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|64|3.7%|38.3%|
[et_compromised](#et_compromised)|1718|1718|58|3.3%|34.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|22|12.5%|13.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|19|0.0%|11.3%|
[firehol_level1](#firehol_level1)|5146|688981376|17|0.0%|10.1%|
[et_block](#et_block)|999|18343755|17|0.0%|10.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|3.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[dshield](#dshield)|20|5120|3|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2|0.0%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|2|0.0%|1.1%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.5%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.5%|
[ciarmy](#ciarmy)|434|434|1|0.2%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|1|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|1|0.0%|0.5%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Wed Jun 10 08:07:00 UTC 2015.

The ipset `openbl_30d` has **2854** entries, **2854** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7028|7028|2854|40.6%|100.0%|
[firehol_level3](#firehol_level3)|109898|9627580|2854|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|2831|1.5%|99.1%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|942|54.7%|33.0%|
[et_compromised](#et_compromised)|1718|1718|937|54.5%|32.8%|
[firehol_level2](#firehol_level2)|24120|35737|842|2.3%|29.5%|
[blocklist_de](#blocklist_de)|30139|30139|801|2.6%|28.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|769|23.2%|26.9%|
[openbl_7d](#openbl_7d)|697|697|697|100.0%|24.4%|
[shunlist](#shunlist)|1340|1340|549|40.9%|19.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|295|0.0%|10.3%|
[openbl_1d](#openbl_1d)|167|167|166|99.4%|5.8%|
[firehol_level1](#firehol_level1)|5146|688981376|159|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|148|0.0%|5.1%|
[et_block](#et_block)|999|18343755|128|0.0%|4.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|120|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|64|0.0%|2.2%|
[dshield](#dshield)|20|5120|37|0.7%|1.2%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|29|0.1%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|24|13.7%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|23|0.9%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|5|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|4|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|4|0.0%|0.1%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[nixspam](#nixspam)|39997|39997|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|434|434|2|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Wed Jun 10 08:07:00 UTC 2015.

The ipset `openbl_60d` has **7028** entries, **7028** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|181943|181943|6999|3.8%|99.5%|
[firehol_level3](#firehol_level3)|109898|9627580|2986|0.0%|42.4%|
[openbl_30d](#openbl_30d)|2854|2854|2854|100.0%|40.6%|
[firehol_level2](#firehol_level2)|24120|35737|1060|2.9%|15.0%|
[et_compromised](#et_compromised)|1718|1718|1004|58.4%|14.2%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1003|58.3%|14.2%|
[blocklist_de](#blocklist_de)|30139|30139|1001|3.3%|14.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|960|29.0%|13.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|747|0.0%|10.6%|
[openbl_7d](#openbl_7d)|697|697|697|100.0%|9.9%|
[shunlist](#shunlist)|1340|1340|577|43.0%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|320|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5146|688981376|288|0.0%|4.0%|
[et_block](#et_block)|999|18343755|247|0.0%|3.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|235|0.0%|3.3%|
[openbl_1d](#openbl_1d)|167|167|166|99.4%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|163|0.0%|2.3%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|51|0.0%|0.7%|
[dshield](#dshield)|20|5120|50|0.9%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|35|0.1%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|27|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|27|1.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|26|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|25|14.2%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|23|0.0%|0.3%|
[et_tor](#et_tor)|6340|6340|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6449|6449|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6449|6449|20|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|19|0.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[firehol_proxies](#firehol_proxies)|11912|12152|18|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|16|0.0%|0.2%|
[php_commenters](#php_commenters)|403|403|11|2.7%|0.1%|
[voipbl](#voipbl)|10522|10934|8|0.0%|0.1%|
[nixspam](#nixspam)|39997|39997|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|4|0.0%|0.0%|
[zeus](#zeus)|231|231|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|434|434|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|1|0.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Wed Jun 10 08:07:00 UTC 2015.

The ipset `openbl_7d` has **697** entries, **697** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7028|7028|697|9.9%|100.0%|
[openbl_30d](#openbl_30d)|2854|2854|697|24.4%|100.0%|
[firehol_level3](#firehol_level3)|109898|9627580|697|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|686|0.3%|98.4%|
[firehol_level2](#firehol_level2)|24120|35737|433|1.2%|62.1%|
[blocklist_de](#blocklist_de)|30139|30139|392|1.3%|56.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|385|11.6%|55.2%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|327|19.0%|46.9%|
[et_compromised](#et_compromised)|1718|1718|318|18.5%|45.6%|
[shunlist](#shunlist)|1340|1340|227|16.9%|32.5%|
[openbl_1d](#openbl_1d)|167|167|166|99.4%|23.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|79|0.0%|11.3%|
[firehol_level1](#firehol_level1)|5146|688981376|54|0.0%|7.7%|
[et_block](#et_block)|999|18343755|53|0.0%|7.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|49|0.0%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|42|0.0%|6.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|24|13.7%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13|0.0%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|7|0.0%|1.0%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|7|0.2%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.7%|
[dshield](#dshield)|20|5120|5|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2|0.0%|0.2%|
[ciarmy](#ciarmy)|434|434|2|0.4%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|2|0.0%|0.2%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.1%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|1|0.1%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun 10 09:00:23 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5146|688981376|13|0.0%|100.0%|
[et_block](#et_block)|999|18343755|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|109898|9627580|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 09:09:07 UTC 2015.

The ipset `php_commenters` has **403** entries, **403** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109898|9627580|403|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|302|0.3%|74.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|225|0.7%|55.8%|
[firehol_level2](#firehol_level2)|24120|35737|184|0.5%|45.6%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|160|2.3%|39.7%|
[blocklist_de](#blocklist_de)|30139|30139|99|0.3%|24.5%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|79|2.6%|19.6%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|76|0.0%|18.8%|
[firehol_proxies](#firehol_proxies)|11912|12152|69|0.5%|17.1%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|58|0.5%|14.3%|
[et_tor](#et_tor)|6340|6340|48|0.7%|11.9%|
[dm_tor](#dm_tor)|6449|6449|48|0.7%|11.9%|
[bm_tor](#bm_tor)|6449|6449|48|0.7%|11.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|45|25.7%|11.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|44|11.8%|10.9%|
[php_spammers](#php_spammers)|661|661|43|6.5%|10.6%|
[firehol_level1](#firehol_level1)|5146|688981376|37|0.0%|9.1%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|31|0.2%|7.6%|
[et_block](#et_block)|999|18343755|30|0.0%|7.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|7.1%|
[php_dictionary](#php_dictionary)|666|666|28|4.2%|6.9%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|26|0.1%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|25|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|23|0.3%|5.7%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|18|0.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|3.9%|
[php_harvesters](#php_harvesters)|378|378|15|3.9%|3.7%|
[openbl_60d](#openbl_60d)|7028|7028|11|0.1%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|10|0.2%|2.4%|
[xroxy](#xroxy)|2148|2148|8|0.3%|1.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|1.7%|
[proxz](#proxz)|1191|1191|7|0.5%|1.7%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|5|0.1%|1.2%|
[nixspam](#nixspam)|39997|39997|5|0.0%|1.2%|
[proxyrss](#proxyrss)|1438|1438|4|0.2%|0.9%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.2%|
[zeus](#zeus)|231|231|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|697|697|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2854|2854|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|167|167|1|0.5%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 09:09:09 UTC 2015.

The ipset `php_dictionary` has **666** entries, **666** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109898|9627580|666|0.0%|100.0%|
[php_spammers](#php_spammers)|661|661|273|41.3%|40.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|126|0.1%|18.9%|
[firehol_level2](#firehol_level2)|24120|35737|108|0.3%|16.2%|
[blocklist_de](#blocklist_de)|30139|30139|102|0.3%|15.3%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|89|0.1%|13.3%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|88|0.8%|13.2%|
[firehol_proxies](#firehol_proxies)|11912|12152|88|0.7%|13.2%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|84|0.2%|12.6%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|83|0.4%|12.4%|
[nixspam](#nixspam)|39997|39997|74|0.1%|11.1%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|60|0.8%|9.0%|
[xroxy](#xroxy)|2148|2148|39|1.8%|5.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|35|0.0%|5.2%|
[php_commenters](#php_commenters)|403|403|28|6.9%|4.2%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|25|0.3%|3.7%|
[proxz](#proxz)|1191|1191|23|1.9%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|22|0.0%|3.3%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|16|0.5%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|1.8%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|8|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.9%|
[firehol_level1](#firehol_level1)|5146|688981376|6|0.0%|0.9%|
[et_block](#et_block)|999|18343755|6|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|4|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|4|2.2%|0.6%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[et_tor](#et_tor)|6340|6340|3|0.0%|0.4%|
[dm_tor](#dm_tor)|6449|6449|3|0.0%|0.4%|
[bm_tor](#bm_tor)|6449|6449|3|0.0%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|3|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|3|0.0%|0.4%|
[proxyrss](#proxyrss)|1438|1438|2|0.1%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 09:09:05 UTC 2015.

The ipset `php_harvesters` has **378** entries, **378** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109898|9627580|378|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|81|0.0%|21.4%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|60|0.2%|15.8%|
[firehol_level2](#firehol_level2)|24120|35737|58|0.1%|15.3%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|42|0.6%|11.1%|
[blocklist_de](#blocklist_de)|30139|30139|38|0.1%|10.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|27|0.8%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|5.2%|
[php_commenters](#php_commenters)|403|403|15|3.7%|3.9%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|12|0.0%|3.1%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|12|0.0%|3.1%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|11|0.1%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|2.9%|
[firehol_proxies](#firehol_proxies)|11912|12152|11|0.0%|2.9%|
[nixspam](#nixspam)|39997|39997|9|0.0%|2.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.3%|
[et_tor](#et_tor)|6340|6340|7|0.1%|1.8%|
[dm_tor](#dm_tor)|6449|6449|7|0.1%|1.8%|
[bm_tor](#bm_tor)|6449|6449|7|0.1%|1.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|6|0.0%|1.5%|
[php_spammers](#php_spammers)|661|661|3|0.4%|0.7%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.7%|
[firehol_level1](#firehol_level1)|5146|688981376|3|0.0%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|3|0.3%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|3|0.0%|0.7%|
[xroxy](#xroxy)|2148|2148|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|2|0.0%|0.5%|
[openbl_60d](#openbl_60d)|7028|7028|2|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|2|1.1%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[proxyrss](#proxyrss)|1438|1438|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.2%|
[et_block](#et_block)|999|18343755|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Wed Jun 10 09:09:06 UTC 2015.

The ipset `php_spammers` has **661** entries, **661** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109898|9627580|661|0.0%|100.0%|
[php_dictionary](#php_dictionary)|666|666|273|40.9%|41.3%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|138|0.1%|20.8%|
[firehol_level2](#firehol_level2)|24120|35737|105|0.2%|15.8%|
[blocklist_de](#blocklist_de)|30139|30139|99|0.3%|14.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|83|0.2%|12.5%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|82|0.7%|12.4%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|76|0.0%|11.4%|
[firehol_proxies](#firehol_proxies)|11912|12152|74|0.6%|11.1%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|74|0.3%|11.1%|
[nixspam](#nixspam)|39997|39997|59|0.1%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|52|0.0%|7.8%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|50|0.6%|7.5%|
[php_commenters](#php_commenters)|403|403|43|10.6%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|41|0.0%|6.2%|
[xroxy](#xroxy)|2148|2148|32|1.4%|4.8%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|31|0.4%|4.6%|
[proxz](#proxz)|1191|1191|21|1.7%|3.1%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|17|0.5%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|7|4.0%|1.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|7|0.2%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|7|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|5|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.6%|
[proxyrss](#proxyrss)|1438|1438|4|0.2%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[firehol_level1](#firehol_level1)|5146|688981376|4|0.0%|0.6%|
[et_tor](#et_tor)|6340|6340|4|0.0%|0.6%|
[et_block](#et_block)|999|18343755|4|0.0%|0.6%|
[dm_tor](#dm_tor)|6449|6449|4|0.0%|0.6%|
[bm_tor](#bm_tor)|6449|6449|4|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|3|0.1%|0.4%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[openbl_7d](#openbl_7d)|697|697|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7028|7028|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2854|2854|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|167|167|1|0.5%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Wed Jun 10 07:01:25 UTC 2015.

The ipset `proxyrss` has **1438** entries, **1438** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11912|12152|1438|11.8%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|1438|1.7%|100.0%|
[firehol_level3](#firehol_level3)|109898|9627580|680|0.0%|47.2%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|679|0.7%|47.2%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|597|7.9%|41.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|562|1.9%|39.0%|
[firehol_level2](#firehol_level2)|24120|35737|415|1.1%|28.8%|
[xroxy](#xroxy)|2148|2148|341|15.8%|23.7%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|341|4.9%|23.7%|
[proxz](#proxz)|1191|1191|268|22.5%|18.6%|
[blocklist_de](#blocklist_de)|30139|30139|232|0.7%|16.1%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|231|7.6%|16.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|190|7.0%|13.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|57|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|46|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|28|0.0%|1.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|10|1.5%|0.6%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|6|0.0%|0.4%|
[nixspam](#nixspam)|39997|39997|6|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|6|3.4%|0.4%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.2%|
[php_commenters](#php_commenters)|403|403|4|0.9%|0.2%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|3|0.0%|0.2%|
[php_dictionary](#php_dictionary)|666|666|2|0.3%|0.1%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Wed Jun 10 07:01:30 UTC 2015.

The ipset `proxz` has **1191** entries, **1191** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11912|12152|1191|9.8%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|1191|1.4%|100.0%|
[firehol_level3](#firehol_level3)|109898|9627580|712|0.0%|59.7%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|705|0.7%|59.1%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|547|7.3%|45.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|480|1.6%|40.3%|
[xroxy](#xroxy)|2148|2148|428|19.9%|35.9%|
[proxyrss](#proxyrss)|1438|1438|268|18.6%|22.5%|
[firehol_level2](#firehol_level2)|24120|35737|256|0.7%|21.4%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|203|7.5%|17.0%|
[blocklist_de](#blocklist_de)|30139|30139|177|0.5%|14.8%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|176|2.5%|14.7%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|147|4.8%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|99|0.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|49|0.0%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|41|0.0%|3.4%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|30|0.1%|2.5%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|26|0.2%|2.1%|
[php_dictionary](#php_dictionary)|666|666|23|3.4%|1.9%|
[php_spammers](#php_spammers)|661|661|21|3.1%|1.7%|
[nixspam](#nixspam)|39997|39997|21|0.0%|1.7%|
[php_commenters](#php_commenters)|403|403|7|1.7%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|5|2.8%|0.4%|
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
[firehol_proxies](#firehol_proxies)|11912|12152|2703|22.2%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|2703|3.2%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1528|1.6%|56.5%|
[firehol_level3](#firehol_level3)|109898|9627580|1528|0.0%|56.5%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|1149|15.3%|42.5%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|582|1.9%|21.5%|
[xroxy](#xroxy)|2148|2148|389|18.1%|14.3%|
[proxz](#proxz)|1191|1191|203|17.0%|7.5%|
[proxyrss](#proxyrss)|1438|1438|190|13.2%|7.0%|
[firehol_level2](#firehol_level2)|24120|35737|149|0.4%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|103|1.4%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|103|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|83|0.0%|3.0%|
[blocklist_de](#blocklist_de)|30139|30139|78|0.2%|2.8%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|74|2.4%|2.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|57|0.0%|2.1%|
[nixspam](#nixspam)|39997|39997|7|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|5|0.0%|0.1%|
[php_commenters](#php_commenters)|403|403|5|1.2%|0.1%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|4|0.0%|0.1%|
[php_spammers](#php_spammers)|661|661|3|0.4%|0.1%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|3|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|2|0.0%|0.0%|
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
[firehol_proxies](#firehol_proxies)|11912|12152|7484|61.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|7484|9.0%|100.0%|
[firehol_level3](#firehol_level3)|109898|9627580|3593|0.0%|48.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|3547|3.7%|47.3%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1527|5.2%|20.4%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|1149|42.5%|15.3%|
[xroxy](#xroxy)|2148|2148|943|43.9%|12.6%|
[firehol_level2](#firehol_level2)|24120|35737|654|1.8%|8.7%|
[proxyrss](#proxyrss)|1438|1438|597|41.5%|7.9%|
[proxz](#proxz)|1191|1191|547|45.9%|7.3%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|452|6.5%|6.0%|
[blocklist_de](#blocklist_de)|30139|30139|424|1.4%|5.6%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|351|11.6%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|219|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|214|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|152|0.0%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|67|0.3%|0.8%|
[nixspam](#nixspam)|39997|39997|62|0.1%|0.8%|
[php_dictionary](#php_dictionary)|666|666|60|9.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|59|0.5%|0.7%|
[php_spammers](#php_spammers)|661|661|50|7.5%|0.6%|
[php_commenters](#php_commenters)|403|403|23|5.7%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|14|2.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|6|3.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|6|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|6|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6449|6449|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6449|6449|4|0.0%|0.0%|
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

The last time downloaded was found to be dated: Wed Jun 10 07:30:04 UTC 2015.

The ipset `shunlist` has **1340** entries, **1340** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109898|9627580|1340|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|1328|0.7%|99.1%|
[openbl_60d](#openbl_60d)|7028|7028|577|8.2%|43.0%|
[openbl_30d](#openbl_30d)|2854|2854|549|19.2%|40.9%|
[firehol_level2](#firehol_level2)|24120|35737|465|1.3%|34.7%|
[blocklist_de](#blocklist_de)|30139|30139|460|1.5%|34.3%|
[et_compromised](#et_compromised)|1718|1718|451|26.2%|33.6%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|450|26.1%|33.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|419|12.6%|31.2%|
[openbl_7d](#openbl_7d)|697|697|227|32.5%|16.9%|
[firehol_level1](#firehol_level1)|5146|688981376|187|0.0%|13.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|121|0.0%|9.0%|
[et_block](#et_block)|999|18343755|111|0.0%|8.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|98|0.0%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|77|0.0%|5.7%|
[openbl_1d](#openbl_1d)|167|167|67|40.1%|5.0%|
[sslbl](#sslbl)|375|375|64|17.0%|4.7%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|36|0.2%|2.6%|
[ciarmy](#ciarmy)|434|434|29|6.6%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|27|0.0%|2.0%|
[dshield](#dshield)|20|5120|25|0.4%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|19|10.8%|1.4%|
[voipbl](#voipbl)|10522|10934|14|0.1%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|4|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|3|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|2|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|2|2.5%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[firehol_proxies](#firehol_proxies)|11912|12152|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|1|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6449|6449|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6449|6449|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109898|9627580|10254|0.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|1163|1.4%|11.3%|
[et_tor](#et_tor)|6340|6340|1068|16.8%|10.4%|
[bm_tor](#bm_tor)|6449|6449|1063|16.4%|10.3%|
[dm_tor](#dm_tor)|6449|6449|1061|16.4%|10.3%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|808|0.8%|7.8%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|669|2.2%|6.5%|
[nixspam](#nixspam)|39997|39997|625|1.5%|6.0%|
[firehol_level2](#firehol_level2)|24120|35737|577|1.6%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|406|5.8%|3.9%|
[firehol_level1](#firehol_level1)|5146|688981376|300|0.0%|2.9%|
[et_block](#et_block)|999|18343755|299|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|256|0.0%|2.4%|
[firehol_proxies](#firehol_proxies)|11912|12152|254|2.0%|2.4%|
[blocklist_de](#blocklist_de)|30139|30139|208|0.6%|2.0%|
[zeus](#zeus)|231|231|201|87.0%|1.9%|
[zeus_badips](#zeus_badips)|203|203|179|88.1%|1.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|170|45.6%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|164|0.0%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|163|0.8%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|118|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|116|0.0%|1.1%|
[php_dictionary](#php_dictionary)|666|666|88|13.2%|0.8%|
[php_spammers](#php_spammers)|661|661|82|12.4%|0.7%|
[feodo](#feodo)|104|104|82|78.8%|0.7%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|59|0.7%|0.5%|
[php_commenters](#php_commenters)|403|403|58|14.3%|0.5%|
[xroxy](#xroxy)|2148|2148|44|2.0%|0.4%|
[sslbl](#sslbl)|375|375|32|8.5%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|28|0.1%|0.2%|
[proxz](#proxz)|1191|1191|26|2.1%|0.2%|
[openbl_60d](#openbl_60d)|7028|7028|26|0.3%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|24|0.6%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|20|0.6%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|19|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|14|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|13|1.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|11|2.9%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|7|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[proxyrss](#proxyrss)|1438|1438|6|0.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|5|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|4|0.1%|0.0%|
[shunlist](#shunlist)|1340|1340|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|2|1.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|2|1.1%|0.0%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109898|9627580|6933035|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3778|670299624|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|1373|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1023|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|294|1.0%|0.0%|
[firehol_level2](#firehol_level2)|24120|35737|272|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7028|7028|235|3.3%|0.0%|
[blocklist_de](#blocklist_de)|30139|30139|202|0.6%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|120|4.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|118|3.5%|0.0%|
[et_compromised](#et_compromised)|1718|1718|101|5.8%|0.0%|
[shunlist](#shunlist)|1340|1340|98|7.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|95|5.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|87|1.2%|0.0%|
[nixspam](#nixspam)|39997|39997|82|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|56|1.8%|0.0%|
[openbl_7d](#openbl_7d)|697|697|49|7.0%|0.0%|
[php_commenters](#php_commenters)|403|403|29|7.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|21|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|19|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|16|7.8%|0.0%|
[zeus](#zeus)|231|231|16|6.9%|0.0%|
[voipbl](#voipbl)|10522|10934|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|167|167|14|8.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|13|0.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|8|4.5%|0.0%|
[php_dictionary](#php_dictionary)|666|666|6|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|5|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[malc0de](#malc0de)|338|338|4|1.1%|0.0%|
[et_tor](#et_tor)|6340|6340|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6449|6449|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6449|6449|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11912|12152|2|0.0%|0.0%|
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
[firehol_level3](#firehol_level3)|109898|9627580|89|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|79|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|14|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|9|0.0%|0.0%|
[firehol_level2](#firehol_level2)|24120|35737|9|0.0%|0.0%|
[php_commenters](#php_commenters)|403|403|7|1.7%|0.0%|
[blocklist_de](#blocklist_de)|30139|30139|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|5|2.4%|0.0%|
[zeus](#zeus)|231|231|5|2.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|5|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|4|2.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|3|0.0%|0.0%|
[nixspam](#nixspam)|39997|39997|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7028|7028|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|1|0.0%|0.0%|
[malc0de](#malc0de)|338|338|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Wed Jun 10 08:45:06 UTC 2015.

The ipset `sslbl` has **375** entries, **375** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5146|688981376|375|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109898|9627580|96|0.0%|25.6%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|66|0.0%|17.6%|
[shunlist](#shunlist)|1340|1340|64|4.7%|17.0%|
[et_block](#et_block)|999|18343755|38|0.0%|10.1%|
[feodo](#feodo)|104|104|37|35.5%|9.8%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|32|0.3%|8.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|28|0.0%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11912|12152|1|0.0%|0.2%|
[firehol_level2](#firehol_level2)|24120|35737|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|30139|30139|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Wed Jun 10 09:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6941** entries, **6941** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|24120|35737|6941|19.4%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|5791|19.7%|83.4%|
[firehol_level3](#firehol_level3)|109898|9627580|4674|0.0%|67.3%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|4634|4.9%|66.7%|
[blocklist_de](#blocklist_de)|30139|30139|1384|4.5%|19.9%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|1307|43.3%|18.8%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|1013|1.2%|14.5%|
[firehol_proxies](#firehol_proxies)|11912|12152|793|6.5%|11.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|472|0.0%|6.8%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|452|6.0%|6.5%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|406|3.9%|5.8%|
[et_tor](#et_tor)|6340|6340|363|5.7%|5.2%|
[bm_tor](#bm_tor)|6449|6449|362|5.6%|5.2%|
[dm_tor](#dm_tor)|6449|6449|360|5.5%|5.1%|
[proxyrss](#proxyrss)|1438|1438|341|23.7%|4.9%|
[xroxy](#xroxy)|2148|2148|230|10.7%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|212|0.0%|3.0%|
[proxz](#proxz)|1191|1191|176|14.7%|2.5%|
[php_commenters](#php_commenters)|403|403|160|39.7%|2.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|156|41.9%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|134|0.0%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|107|61.1%|1.5%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|103|3.8%|1.4%|
[firehol_level1](#firehol_level1)|5146|688981376|89|0.0%|1.2%|
[et_block](#et_block)|999|18343755|89|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|87|0.0%|1.2%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|74|0.4%|1.0%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|48|0.0%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|44|1.2%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|43|0.2%|0.6%|
[php_harvesters](#php_harvesters)|378|378|42|11.1%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|38|0.0%|0.5%|
[php_spammers](#php_spammers)|661|661|31|4.6%|0.4%|
[php_dictionary](#php_dictionary)|666|666|25|3.7%|0.3%|
[nixspam](#nixspam)|39997|39997|24|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7028|7028|19|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|10|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|4|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[shunlist](#shunlist)|1340|1340|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109898|9627580|93938|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|27990|95.4%|29.7%|
[firehol_level2](#firehol_level2)|24120|35737|6004|16.8%|6.3%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|5939|7.2%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5824|0.0%|6.1%|
[firehol_proxies](#firehol_proxies)|11912|12152|5295|43.5%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|4634|66.7%|4.9%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|3547|47.3%|3.7%|
[blocklist_de](#blocklist_de)|30139|30139|2538|8.4%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2502|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|2162|71.7%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|1528|56.5%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1519|0.0%|1.6%|
[xroxy](#xroxy)|2148|2148|1269|59.0%|1.3%|
[firehol_level1](#firehol_level1)|5146|688981376|1102|0.0%|1.1%|
[et_block](#et_block)|999|18343755|1029|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1023|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|808|7.8%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|735|0.0%|0.7%|
[proxz](#proxz)|1191|1191|705|59.1%|0.7%|
[proxyrss](#proxyrss)|1438|1438|679|47.2%|0.7%|
[et_tor](#et_tor)|6340|6340|642|10.1%|0.6%|
[bm_tor](#bm_tor)|6449|6449|635|9.8%|0.6%|
[dm_tor](#dm_tor)|6449|6449|633|9.8%|0.6%|
[php_commenters](#php_commenters)|403|403|302|74.9%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|268|1.4%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|233|62.6%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|223|1.5%|0.2%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|205|0.1%|0.2%|
[php_spammers](#php_spammers)|661|661|138|20.8%|0.1%|
[nixspam](#nixspam)|39997|39997|132|0.3%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|130|74.2%|0.1%|
[php_dictionary](#php_dictionary)|666|666|126|18.9%|0.1%|
[php_harvesters](#php_harvesters)|378|378|81|21.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|79|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|75|2.1%|0.0%|
[openbl_60d](#openbl_60d)|7028|7028|51|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|48|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|35|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|25|0.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|18|2.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|13|0.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|13|0.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|12|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|11|1.1%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|5|0.1%|0.0%|
[shunlist](#shunlist)|1340|1340|4|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|2|0.9%|0.0%|
[zeus](#zeus)|231|231|2|0.8%|0.0%|
[openbl_7d](#openbl_7d)|697|697|2|0.2%|0.0%|
[openbl_1d](#openbl_1d)|167|167|2|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|434|434|2|0.4%|0.0%|
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
[firehol_level3](#firehol_level3)|109898|9627580|28011|0.2%|95.4%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|27990|29.7%|95.4%|
[firehol_level2](#firehol_level2)|24120|35737|6779|18.9%|23.1%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|5791|83.4%|19.7%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|2740|3.3%|9.3%|
[firehol_proxies](#firehol_proxies)|11912|12152|2332|19.1%|7.9%|
[blocklist_de](#blocklist_de)|30139|30139|2267|7.5%|7.7%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|2056|68.2%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1913|0.0%|6.5%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|1527|20.4%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|790|0.0%|2.6%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|669|6.5%|2.2%|
[xroxy](#xroxy)|2148|2148|623|29.0%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|582|21.5%|1.9%|
[proxyrss](#proxyrss)|1438|1438|562|39.0%|1.9%|
[et_tor](#et_tor)|6340|6340|533|8.4%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|529|0.0%|1.8%|
[bm_tor](#bm_tor)|6449|6449|527|8.1%|1.7%|
[dm_tor](#dm_tor)|6449|6449|525|8.1%|1.7%|
[proxz](#proxz)|1191|1191|480|40.3%|1.6%|
[firehol_level1](#firehol_level1)|5146|688981376|302|0.0%|1.0%|
[et_block](#et_block)|999|18343755|297|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|294|0.0%|1.0%|
[php_commenters](#php_commenters)|403|403|225|55.8%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|192|51.6%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|167|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|148|0.7%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|136|0.9%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|116|66.2%|0.3%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|103|0.0%|0.3%|
[php_dictionary](#php_dictionary)|666|666|84|12.6%|0.2%|
[php_spammers](#php_spammers)|661|661|83|12.5%|0.2%|
[nixspam](#nixspam)|39997|39997|66|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|62|1.7%|0.2%|
[php_harvesters](#php_harvesters)|378|378|60|15.8%|0.2%|
[openbl_60d](#openbl_60d)|7028|7028|27|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|18|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|14|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|9|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|7|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|942|942|7|0.7%|0.0%|
[et_compromised](#et_compromised)|1718|1718|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|5|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|4|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|231|231|1|0.4%|0.0%|
[shunlist](#shunlist)|1340|1340|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|1|0.0%|0.0%|
[ciarmy](#ciarmy)|434|434|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Wed Jun 10 08:42:04 UTC 2015.

The ipset `virbl` has **27** entries, **27** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|109898|9627580|27|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4|0.0%|14.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2|0.0%|7.4%|

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
[firehol_anonymous](#firehol_anonymous)|18393|82416|78|0.0%|0.7%|
[firehol_level3](#firehol_level3)|109898|9627580|59|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|35|0.0%|0.3%|
[firehol_level2](#firehol_level2)|24120|35737|30|0.0%|0.2%|
[blocklist_de](#blocklist_de)|30139|30139|28|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|80|80|24|30.0%|0.2%|
[et_block](#et_block)|999|18343755|18|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|14|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|0.1%|
[shunlist](#shunlist)|1340|1340|14|1.0%|0.1%|
[openbl_60d](#openbl_60d)|7028|7028|8|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2854|2854|3|0.1%|0.0%|
[et_tor](#et_tor)|6340|6340|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6449|6449|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6449|6449|3|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|2|0.0%|0.0%|
[nixspam](#nixspam)|39997|39997|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3304|3304|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14825|14825|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11912|12152|1|0.0%|0.0%|
[ciarmy](#ciarmy)|434|434|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|3468|3468|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Wed Jun 10 08:33:01 UTC 2015.

The ipset `xroxy` has **2148** entries, **2148** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11912|12152|2148|17.6%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18393|82416|2148|2.6%|100.0%|
[firehol_level3](#firehol_level3)|109898|9627580|1286|0.0%|59.8%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|1269|1.3%|59.0%|
[ri_web_proxies](#ri_web_proxies)|7484|7484|943|12.6%|43.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|623|2.1%|29.0%|
[proxz](#proxz)|1191|1191|428|35.9%|19.9%|
[ri_connect_proxies](#ri_connect_proxies)|2703|2703|389|14.3%|18.1%|
[proxyrss](#proxyrss)|1438|1438|341|23.7%|15.8%|
[firehol_level2](#firehol_level2)|24120|35737|328|0.9%|15.2%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|230|3.3%|10.7%|
[blocklist_de](#blocklist_de)|30139|30139|207|0.6%|9.6%|
[blocklist_de_bots](#blocklist_de_bots)|3012|3012|152|5.0%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|107|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|55|0.2%|2.5%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|44|0.4%|2.0%|
[php_dictionary](#php_dictionary)|666|666|39|5.8%|1.8%|
[nixspam](#nixspam)|39997|39997|39|0.0%|1.8%|
[php_spammers](#php_spammers)|661|661|32|4.8%|1.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[php_commenters](#php_commenters)|403|403|8|1.9%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|6|3.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|5|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1718|1718|1|0.0%|0.0%|
[et_block](#et_block)|999|18343755|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6449|6449|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1720|1720|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6449|6449|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2511|2511|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|109898|9627580|204|0.0%|88.3%|
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
[openbl_60d](#openbl_60d)|7028|7028|2|0.0%|0.8%|
[firehol_level2](#firehol_level2)|24120|35737|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|1|0.0%|0.4%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.4%|
[openbl_30d](#openbl_30d)|2854|2854|1|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|30139|30139|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Wed Jun 10 09:00:21 UTC 2015.

The ipset `zeus_badips` has **203** entries, **203** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|231|231|203|87.8%|100.0%|
[firehol_level1](#firehol_level1)|5146|688981376|203|0.0%|100.0%|
[et_block](#et_block)|999|18343755|203|0.0%|100.0%|
[firehol_level3](#firehol_level3)|109898|9627580|181|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|10254|10254|179|1.7%|88.1%|
[alienvault_reputation](#alienvault_reputation)|181943|181943|38|0.0%|18.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|16|0.0%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|93938|93938|2|0.0%|0.9%|
[firehol_level2](#firehol_level2)|24120|35737|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29338|29338|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6941|6941|1|0.0%|0.4%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7028|7028|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|19046|19046|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|30139|30139|1|0.0%|0.4%|
