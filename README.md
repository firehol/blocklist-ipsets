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

The following list was automatically generated on Mon Jun  8 23:37:39 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|178836 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|32230 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|16804 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3503 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|5481 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|133 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2434 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|19540 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|92 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|3279 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|163 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6437 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1716 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|445 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|123 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6418 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|999 subnets, 18343755 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|509 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1678 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6400 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|102 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)|ipv4 hash:net|18108 subnets, 82117 unique IPs|updated every 1 min  from [this link]()
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5089 subnets, 688943412 unique IPs|updated every 1 min  from [this link]()
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|26368 subnets, 38001 unique IPs|updated every 1 min  from [this link]()
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)|ipv4 hash:net|107701 subnets, 9625160 unique IPs|updated every 1 min  from [this link]()
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|11630 subnets, 11854 unique IPs|updated every 1 min  from [this link]()
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|39998 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|135 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2882 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7208 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|824 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|385 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|630 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|366 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|622 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1501 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1080 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2617 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7198 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1231 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9624 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|652 subnets, 18338560 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|380 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7133 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92247 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29278 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|13 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10507 subnets, 10919 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2136 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|232 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|203 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Mon Jun  8 22:01:21 UTC 2015.

The ipset `alienvault_reputation` has **178836** entries, **178836** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13855|0.0%|7.7%|
[openbl_60d](#openbl_60d)|7208|7208|7188|99.7%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6255|0.0%|3.4%|
[et_block](#et_block)|999|18343755|5280|0.0%|2.9%|
[firehol_level3](#firehol_level3)|107701|9625160|5180|0.0%|2.8%|
[firehol_level1](#firehol_level1)|5089|688943412|4336|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4131|0.0%|2.3%|
[dshield](#dshield)|20|5120|3074|60.0%|1.7%|
[openbl_30d](#openbl_30d)|2882|2882|2868|99.5%|1.6%|
[firehol_level2](#firehol_level2)|26368|38001|1539|4.0%|0.8%|
[blocklist_de](#blocklist_de)|32230|32230|1473|4.5%|0.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1374|0.0%|0.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|1245|37.9%|0.6%|
[shunlist](#shunlist)|1231|1231|1224|99.4%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|1093|63.6%|0.6%|
[et_compromised](#et_compromised)|1678|1678|1076|64.1%|0.6%|
[openbl_7d](#openbl_7d)|824|824|819|99.3%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|445|445|440|98.8%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|288|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|197|0.2%|0.1%|
[voipbl](#voipbl)|10507|10919|189|1.7%|0.1%|
[openbl_1d](#openbl_1d)|135|135|131|97.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|123|1.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|121|0.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|96|0.3%|0.0%|
[sslbl](#sslbl)|380|380|68|17.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|68|0.3%|0.0%|
[zeus](#zeus)|232|232|63|27.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|54|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|52|0.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|46|1.8%|0.0%|
[nixspam](#nixspam)|39998|39998|45|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|41|0.6%|0.0%|
[dm_tor](#dm_tor)|6418|6418|41|0.6%|0.0%|
[bm_tor](#bm_tor)|6437|6437|41|0.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|38|18.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|37|22.6%|0.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|32|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|31|0.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|19|0.3%|0.0%|
[php_commenters](#php_commenters)|385|385|17|4.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|15|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|15|16.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|14|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|11|3.0%|0.0%|
[malc0de](#malc0de)|342|342|10|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|10|0.6%|0.0%|
[php_dictionary](#php_dictionary)|630|630|8|1.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|133|133|8|6.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|7|0.5%|0.0%|
[php_spammers](#php_spammers)|622|622|5|0.8%|0.0%|
[et_botcc](#et_botcc)|509|509|5|0.9%|0.0%|
[xroxy](#xroxy)|2136|2136|4|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|3|0.1%|0.0%|
[proxz](#proxz)|1080|1080|3|0.2%|0.0%|
[proxyrss](#proxyrss)|1501|1501|2|0.1%|0.0%|
[feodo](#feodo)|102|102|2|1.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|2|1.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Mon Jun  8 23:28:04 UTC 2015.

The ipset `blocklist_de` has **32230** entries, **32230** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26368|38001|32230|84.8%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|19516|99.8%|60.5%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|16804|100.0%|52.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|5481|100.0%|17.0%|
[firehol_level3](#firehol_level3)|107701|9625160|3891|0.0%|12.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3775|0.0%|11.7%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|3488|99.5%|10.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|3243|98.9%|10.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2457|2.6%|7.6%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|2418|99.3%|7.5%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|2055|7.0%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1604|0.0%|4.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1573|0.0%|4.8%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|1473|0.8%|4.5%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|1390|19.4%|4.3%|
[openbl_60d](#openbl_60d)|7208|7208|1127|15.6%|3.4%|
[nixspam](#nixspam)|39998|39998|1047|2.6%|3.2%|
[openbl_30d](#openbl_30d)|2882|2882|868|30.1%|2.6%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|738|43.0%|2.2%|
[et_compromised](#et_compromised)|1678|1678|672|40.0%|2.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|597|0.7%|1.8%|
[firehol_proxies](#firehol_proxies)|11630|11854|593|5.0%|1.8%|
[shunlist](#shunlist)|1231|1231|436|35.4%|1.3%|
[openbl_7d](#openbl_7d)|824|824|414|50.2%|1.2%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|403|5.5%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|296|3.0%|0.9%|
[firehol_level1](#firehol_level1)|5089|688943412|206|0.0%|0.6%|
[xroxy](#xroxy)|2136|2136|202|9.4%|0.6%|
[et_block](#et_block)|999|18343755|195|0.0%|0.6%|
[proxyrss](#proxyrss)|1501|1501|193|12.8%|0.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|184|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|163|100.0%|0.5%|
[proxz](#proxz)|1080|1080|157|14.5%|0.4%|
[blocklist_de_ftp](#blocklist_de_ftp)|133|133|128|96.2%|0.3%|
[openbl_1d](#openbl_1d)|135|135|107|79.2%|0.3%|
[php_commenters](#php_commenters)|385|385|94|24.4%|0.2%|
[php_dictionary](#php_dictionary)|630|630|89|14.1%|0.2%|
[dshield](#dshield)|20|5120|86|1.6%|0.2%|
[php_spammers](#php_spammers)|622|622|81|13.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|78|2.9%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|72|78.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|44|0.0%|0.1%|
[php_harvesters](#php_harvesters)|366|366|42|11.4%|0.1%|
[ciarmy](#ciarmy)|445|445|37|8.3%|0.1%|
[voipbl](#voipbl)|10507|10919|32|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|10|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|7|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6418|6418|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6437|6437|4|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Mon Jun  8 23:28:07 UTC 2015.

The ipset `blocklist_de_apache` has **16804** entries, **16804** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26368|38001|16804|44.2%|100.0%|
[blocklist_de](#blocklist_de)|32230|32230|16804|52.1%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|11059|56.5%|65.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|5481|100.0%|32.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2492|0.0%|14.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1327|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1098|0.0%|6.5%|
[firehol_level3](#firehol_level3)|107701|9625160|282|0.0%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|210|0.2%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|124|0.4%|0.7%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|121|0.0%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|60|0.8%|0.3%|
[nixspam](#nixspam)|39998|39998|34|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|34|20.8%|0.2%|
[ciarmy](#ciarmy)|445|445|33|7.4%|0.1%|
[shunlist](#shunlist)|1231|1231|31|2.5%|0.1%|
[php_commenters](#php_commenters)|385|385|31|8.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|21|0.5%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|13|0.1%|0.0%|
[firehol_level1](#firehol_level1)|5089|688943412|12|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|11|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|9|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|8|0.1%|0.0%|
[et_block](#et_block)|999|18343755|7|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|6|0.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|6|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|6|0.0%|0.0%|
[dshield](#dshield)|20|5120|6|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|5|0.7%|0.0%|
[voipbl](#voipbl)|10507|10919|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6418|6418|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6437|6437|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[openbl_60d](#openbl_60d)|7208|7208|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2882|2882|2|0.0%|0.0%|
[xroxy](#xroxy)|2136|2136|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|1|0.0%|0.0%|
[proxz](#proxz)|1080|1080|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Mon Jun  8 23:14:13 UTC 2015.

The ipset `blocklist_de_bots` has **3503** entries, **3503** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26368|38001|3490|9.1%|99.6%|
[blocklist_de](#blocklist_de)|32230|32230|3488|10.8%|99.5%|
[firehol_level3](#firehol_level3)|107701|9625160|2168|0.0%|61.8%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2143|2.3%|61.1%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1895|6.4%|54.0%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|1328|18.6%|37.9%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|511|0.6%|14.5%|
[firehol_proxies](#firehol_proxies)|11630|11854|509|4.2%|14.5%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|347|4.8%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|236|0.0%|6.7%|
[proxyrss](#proxyrss)|1501|1501|194|12.9%|5.5%|
[xroxy](#xroxy)|2136|2136|165|7.7%|4.7%|
[proxz](#proxz)|1080|1080|140|12.9%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|126|0.0%|3.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|120|73.6%|3.4%|
[php_commenters](#php_commenters)|385|385|76|19.7%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|75|2.8%|2.1%|
[nixspam](#nixspam)|39998|39998|47|0.1%|1.3%|
[firehol_level1](#firehol_level1)|5089|688943412|44|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|41|0.0%|1.1%|
[et_block](#et_block)|999|18343755|41|0.0%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|34|0.0%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|33|0.3%|0.9%|
[php_harvesters](#php_harvesters)|366|366|31|8.4%|0.8%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|31|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|29|0.0%|0.8%|
[php_dictionary](#php_dictionary)|630|630|25|3.9%|0.7%|
[php_spammers](#php_spammers)|622|622|22|3.5%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|21|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|21|0.1%|0.5%|
[openbl_60d](#openbl_60d)|7208|7208|15|0.2%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6418|6418|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6437|6437|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Mon Jun  8 23:28:10 UTC 2015.

The ipset `blocklist_de_bruteforce` has **5481** entries, **5481** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26368|38001|5481|14.4%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|5481|32.6%|100.0%|
[blocklist_de](#blocklist_de)|32230|32230|5481|17.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|397|0.0%|7.2%|
[firehol_level3](#firehol_level3)|107701|9625160|78|0.0%|1.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|63|0.0%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|61|0.0%|1.1%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|40|0.1%|0.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|38|0.0%|0.6%|
[nixspam](#nixspam)|39998|39998|34|0.0%|0.6%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|27|0.3%|0.4%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|19|0.0%|0.3%|
[php_commenters](#php_commenters)|385|385|11|2.8%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|10|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|9|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|9|5.5%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|8|0.1%|0.1%|
[firehol_proxies](#firehol_proxies)|11630|11854|8|0.0%|0.1%|
[php_spammers](#php_spammers)|622|622|6|0.9%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|6|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|5|0.7%|0.0%|
[firehol_level1](#firehol_level1)|5089|688943412|5|0.0%|0.0%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6418|6418|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6437|6437|2|0.0%|0.0%|
[xroxy](#xroxy)|2136|2136|1|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.0%|
[shunlist](#shunlist)|1231|1231|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|1|0.0%|0.0%|
[proxz](#proxz)|1080|1080|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[ciarmy](#ciarmy)|445|445|1|0.2%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Mon Jun  8 23:14:12 UTC 2015.

The ipset `blocklist_de_ftp` has **133** entries, **133** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26368|38001|128|0.3%|96.2%|
[blocklist_de](#blocklist_de)|32230|32230|128|0.3%|96.2%|
[firehol_level3](#firehol_level3)|107701|9625160|14|0.0%|10.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13|0.0%|9.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|10|0.0%|7.5%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|8|0.0%|6.0%|
[php_harvesters](#php_harvesters)|366|366|6|1.6%|4.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|5|0.0%|3.7%|
[openbl_60d](#openbl_60d)|7208|7208|2|0.0%|1.5%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|1|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|1|0.0%|0.7%|
[openbl_7d](#openbl_7d)|824|824|1|0.1%|0.7%|
[openbl_30d](#openbl_30d)|2882|2882|1|0.0%|0.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|0.7%|
[ciarmy](#ciarmy)|445|445|1|0.2%|0.7%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Mon Jun  8 23:14:12 UTC 2015.

The ipset `blocklist_de_imap` has **2434** entries, **2434** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|2434|12.4%|100.0%|
[firehol_level2](#firehol_level2)|26368|38001|2418|6.3%|99.3%|
[blocklist_de](#blocklist_de)|32230|32230|2418|7.5%|99.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|201|0.0%|8.2%|
[firehol_level3](#firehol_level3)|107701|9625160|59|0.0%|2.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|51|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|46|0.0%|1.8%|
[openbl_60d](#openbl_60d)|7208|7208|35|0.4%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|31|0.0%|1.2%|
[openbl_30d](#openbl_30d)|2882|2882|30|1.0%|1.2%|
[nixspam](#nixspam)|39998|39998|21|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5089|688943412|16|0.0%|0.6%|
[et_block](#et_block)|999|18343755|16|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|15|0.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|14|0.1%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|12|0.0%|0.4%|
[openbl_7d](#openbl_7d)|824|824|11|1.3%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|5|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11630|11854|5|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|5|0.0%|0.2%|
[et_compromised](#et_compromised)|1678|1678|5|0.2%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|5|0.2%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|4|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.1%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|1|0.0%|0.0%|
[shunlist](#shunlist)|1231|1231|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|630|630|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|135|135|1|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[ciarmy](#ciarmy)|445|445|1|0.2%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Mon Jun  8 23:14:10 UTC 2015.

The ipset `blocklist_de_mail` has **19540** entries, **19540** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26368|38001|19516|51.3%|99.8%|
[blocklist_de](#blocklist_de)|32230|32230|19516|60.5%|99.8%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|11059|65.8%|56.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2650|0.0%|13.5%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|2434|100.0%|12.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1419|0.0%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1247|0.0%|6.3%|
[nixspam](#nixspam)|39998|39998|962|2.4%|4.9%|
[firehol_level3](#firehol_level3)|107701|9625160|494|0.0%|2.5%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|251|2.6%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|238|0.2%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|129|0.4%|0.6%|
[firehol_proxies](#firehol_proxies)|11630|11854|79|0.6%|0.4%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|79|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|68|0.0%|0.3%|
[php_dictionary](#php_dictionary)|630|630|59|9.3%|0.3%|
[php_spammers](#php_spammers)|622|622|52|8.3%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|50|0.6%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|47|0.6%|0.2%|
[openbl_60d](#openbl_60d)|7208|7208|47|0.6%|0.2%|
[xroxy](#xroxy)|2136|2136|39|1.8%|0.1%|
[openbl_30d](#openbl_30d)|2882|2882|39|1.3%|0.1%|
[php_commenters](#php_commenters)|385|385|25|6.4%|0.1%|
[firehol_level1](#firehol_level1)|5089|688943412|24|0.0%|0.1%|
[et_block](#et_block)|999|18343755|22|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|22|13.4%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|21|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|21|0.5%|0.1%|
[proxz](#proxz)|1080|1080|17|1.5%|0.0%|
[openbl_7d](#openbl_7d)|824|824|12|1.4%|0.0%|
[et_compromised](#et_compromised)|1678|1678|10|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|9|0.5%|0.0%|
[php_harvesters](#php_harvesters)|366|366|4|1.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[shunlist](#shunlist)|1231|1231|3|0.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|135|135|1|0.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dm_tor](#dm_tor)|6418|6418|1|0.0%|0.0%|
[ciarmy](#ciarmy)|445|445|1|0.2%|0.0%|
[bm_tor](#bm_tor)|6437|6437|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Mon Jun  8 23:14:12 UTC 2015.

The ipset `blocklist_de_sip` has **92** entries, **92** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26368|38001|72|0.1%|78.2%|
[blocklist_de](#blocklist_de)|32230|32230|72|0.2%|78.2%|
[voipbl](#voipbl)|10507|10919|28|0.2%|30.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|17.3%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|15|0.0%|16.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|8.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|6.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.1%|
[firehol_level3](#firehol_level3)|107701|9625160|2|0.0%|2.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|1.0%|
[firehol_level1](#firehol_level1)|5089|688943412|1|0.0%|1.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|1.0%|
[et_block](#et_block)|999|18343755|1|0.0%|1.0%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Mon Jun  8 23:14:09 UTC 2015.

The ipset `blocklist_de_ssh` has **3279** entries, **3279** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26368|38001|3243|8.5%|98.9%|
[blocklist_de](#blocklist_de)|32230|32230|3243|10.0%|98.9%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|1245|0.6%|37.9%|
[firehol_level3](#firehol_level3)|107701|9625160|1095|0.0%|33.3%|
[openbl_60d](#openbl_60d)|7208|7208|1063|14.7%|32.4%|
[openbl_30d](#openbl_30d)|2882|2882|827|28.6%|25.2%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|730|42.5%|22.2%|
[et_compromised](#et_compromised)|1678|1678|663|39.5%|20.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|459|0.0%|13.9%|
[shunlist](#shunlist)|1231|1231|402|32.6%|12.2%|
[openbl_7d](#openbl_7d)|824|824|402|48.7%|12.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|144|0.0%|4.3%|
[firehol_level1](#firehol_level1)|5089|688943412|125|0.0%|3.8%|
[et_block](#et_block)|999|18343755|124|0.0%|3.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|116|0.0%|3.5%|
[openbl_1d](#openbl_1d)|135|135|106|78.5%|3.2%|
[dshield](#dshield)|20|5120|76|1.4%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|74|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|29|17.7%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|19|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|2|0.0%|0.0%|
[nixspam](#nixspam)|39998|39998|2|0.0%|0.0%|
[ciarmy](#ciarmy)|445|445|2|0.4%|0.0%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Mon Jun  8 23:14:14 UTC 2015.

The ipset `blocklist_de_strongips` has **163** entries, **163** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26368|38001|163|0.4%|100.0%|
[blocklist_de](#blocklist_de)|32230|32230|163|0.5%|100.0%|
[firehol_level3](#firehol_level3)|107701|9625160|148|0.0%|90.7%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|120|3.4%|73.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|118|0.1%|72.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|109|0.3%|66.8%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|102|1.4%|62.5%|
[php_commenters](#php_commenters)|385|385|41|10.6%|25.1%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|37|0.0%|22.6%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|34|0.2%|20.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|29|0.8%|17.7%|
[openbl_60d](#openbl_60d)|7208|7208|26|0.3%|15.9%|
[openbl_30d](#openbl_30d)|2882|2882|25|0.8%|15.3%|
[openbl_7d](#openbl_7d)|824|824|24|2.9%|14.7%|
[shunlist](#shunlist)|1231|1231|22|1.7%|13.4%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|22|0.1%|13.4%|
[openbl_1d](#openbl_1d)|135|135|18|13.3%|11.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|9.8%|
[firehol_level1](#firehol_level1)|5089|688943412|9|0.0%|5.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|9|0.1%|5.5%|
[php_spammers](#php_spammers)|622|622|6|0.9%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|3.6%|
[xroxy](#xroxy)|2136|2136|5|0.2%|3.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|3.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|5|0.0%|3.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|5|0.0%|3.0%|
[et_block](#et_block)|999|18343755|5|0.0%|3.0%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|4|0.0%|2.4%|
[proxyrss](#proxyrss)|1501|1501|4|0.2%|2.4%|
[php_dictionary](#php_dictionary)|630|630|4|0.6%|2.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|1.8%|
[proxz](#proxz)|1080|1080|3|0.2%|1.8%|
[nixspam](#nixspam)|39998|39998|3|0.0%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|2|0.0%|1.2%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|1.2%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.6%|
[dshield](#dshield)|20|5120|1|0.0%|0.6%|
[ciarmy](#ciarmy)|445|445|1|0.2%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|1|0.0%|0.6%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Mon Jun  8 23:14:58 UTC 2015.

The ipset `bm_tor` has **6437** entries, **6437** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18108|82117|6437|7.8%|100.0%|
[dm_tor](#dm_tor)|6418|6418|6328|98.5%|98.3%|
[et_tor](#et_tor)|6400|6400|5931|92.6%|92.1%|
[firehol_level3](#firehol_level3)|107701|9625160|1085|0.0%|16.8%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|1048|10.8%|16.2%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|626|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|617|0.0%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|499|1.7%|7.7%|
[firehol_level2](#firehol_level2)|26368|38001|352|0.9%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|351|4.9%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|183|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|166|0.0%|2.5%|
[firehol_proxies](#firehol_proxies)|11630|11854|166|1.4%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|163|43.8%|2.5%|
[php_commenters](#php_commenters)|385|385|43|11.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|41|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7208|7208|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|366|366|7|1.9%|0.1%|
[nixspam](#nixspam)|39998|39998|6|0.0%|0.0%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5089|688943412|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|32230|32230|4|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|3|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|2|0.0%|0.0%|
[xroxy](#xroxy)|2136|2136|1|0.0%|0.0%|
[shunlist](#shunlist)|1231|1231|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5089|688943412|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10507|10919|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|107701|9625160|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|445|445|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Mon Jun  8 23:27:03 UTC 2015.

The ipset `bruteforceblocker` has **1716** entries, **1716** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107701|9625160|1716|0.0%|100.0%|
[et_compromised](#et_compromised)|1678|1678|1638|97.6%|95.4%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|1093|0.6%|63.6%|
[openbl_60d](#openbl_60d)|7208|7208|992|13.7%|57.8%|
[openbl_30d](#openbl_30d)|2882|2882|933|32.3%|54.3%|
[firehol_level2](#firehol_level2)|26368|38001|743|1.9%|43.2%|
[blocklist_de](#blocklist_de)|32230|32230|738|2.2%|43.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|730|22.2%|42.5%|
[shunlist](#shunlist)|1231|1231|425|34.5%|24.7%|
[openbl_7d](#openbl_7d)|824|824|319|38.7%|18.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|153|0.0%|8.9%|
[firehol_level1](#firehol_level1)|5089|688943412|103|0.0%|6.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|101|0.0%|5.8%|
[et_block](#et_block)|999|18343755|101|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|90|0.0%|5.2%|
[dshield](#dshield)|20|5120|60|1.1%|3.4%|
[openbl_1d](#openbl_1d)|135|135|56|41.4%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|51|0.0%|2.9%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|13|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|9|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|6|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|5|0.2%|0.2%|
[nixspam](#nixspam)|39998|39998|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|11630|11854|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|3|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|2|0.0%|0.1%|
[proxz](#proxz)|1080|1080|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[ciarmy](#ciarmy)|445|445|2|0.4%|0.1%|
[xroxy](#xroxy)|2136|2136|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|1|0.6%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Mon Jun  8 22:15:16 UTC 2015.

The ipset `ciarmy` has **445** entries, **445** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107701|9625160|445|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|440|0.2%|98.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|86|0.0%|19.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|47|0.0%|10.5%|
[firehol_level2](#firehol_level2)|26368|38001|38|0.0%|8.5%|
[shunlist](#shunlist)|1231|1231|37|3.0%|8.3%|
[blocklist_de](#blocklist_de)|32230|32230|37|0.1%|8.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|35|0.0%|7.8%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|33|0.1%|7.4%|
[voipbl](#voipbl)|10507|10919|4|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5089|688943412|4|0.0%|0.8%|
[et_block](#et_block)|999|18343755|4|0.0%|0.8%|
[dshield](#dshield)|20|5120|3|0.0%|0.6%|
[et_compromised](#et_compromised)|1678|1678|2|0.1%|0.4%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|2|0.1%|0.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|2|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|824|824|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7208|7208|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|2882|2882|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|135|135|1|0.7%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|1|0.6%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|133|133|1|0.7%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|1|0.0%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Mon Jun  8 20:27:27 UTC 2015.

The ipset `cleanmx_viruses` has **123** entries, **123** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107701|9625160|123|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|12|0.0%|9.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|8.1%|
[malc0de](#malc0de)|342|342|8|2.3%|6.5%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|4|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|1.6%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|2|0.0%|1.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.8%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5089|688943412|1|0.0%|0.8%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Mon Jun  8 23:36:04 UTC 2015.

The ipset `dm_tor` has **6418** entries, **6418** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18108|82117|6418|7.8%|100.0%|
[bm_tor](#bm_tor)|6437|6437|6328|98.3%|98.5%|
[et_tor](#et_tor)|6400|6400|5934|92.7%|92.4%|
[firehol_level3](#firehol_level3)|107701|9625160|1085|0.0%|16.9%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|1048|10.8%|16.3%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|630|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|619|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|502|1.7%|7.8%|
[firehol_level2](#firehol_level2)|26368|38001|352|0.9%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|351|4.9%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|183|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11630|11854|166|1.4%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|165|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|163|43.8%|2.5%|
[php_commenters](#php_commenters)|385|385|43|11.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|41|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7208|7208|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|366|366|7|1.9%|0.1%|
[nixspam](#nixspam)|39998|39998|6|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5089|688943412|5|0.0%|0.0%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|32230|32230|4|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|3|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|2|0.0%|0.0%|
[xroxy](#xroxy)|2136|2136|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1231|1231|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Mon Jun  8 19:55:52 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5089|688943412|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|3074|1.7%|60.0%|
[et_block](#et_block)|999|18343755|1792|0.0%|35.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|512|0.0%|10.0%|
[firehol_level3](#firehol_level3)|107701|9625160|363|0.0%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|256|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|256|0.0%|5.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7208|7208|100|1.3%|1.9%|
[shunlist](#shunlist)|1231|1231|90|7.3%|1.7%|
[openbl_30d](#openbl_30d)|2882|2882|88|3.0%|1.7%|
[firehol_level2](#firehol_level2)|26368|38001|88|0.2%|1.7%|
[blocklist_de](#blocklist_de)|32230|32230|86|0.2%|1.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|76|2.3%|1.4%|
[et_compromised](#et_compromised)|1678|1678|60|3.5%|1.1%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|60|3.4%|1.1%|
[openbl_7d](#openbl_7d)|824|824|11|1.3%|0.2%|
[openbl_1d](#openbl_1d)|135|135|7|5.1%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|6|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|4|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|3|0.0%|0.0%|
[ciarmy](#ciarmy)|445|445|3|0.6%|0.0%|
[malc0de](#malc0de)|342|342|2|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|2|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6418|6418|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6437|6437|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|1|0.6%|0.0%|

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
[firehol_level1](#firehol_level1)|5089|688943412|18340164|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|18338560|100.0%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8533288|2.4%|46.5%|
[firehol_level3](#firehol_level3)|107701|9625160|6933327|72.0%|37.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272541|0.2%|12.3%|
[fullbogons](#fullbogons)|3720|670264216|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130394|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|5280|2.9%|0.0%|
[dshield](#dshield)|20|5120|1792|35.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1041|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1020|1.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|312|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|301|3.1%|0.0%|
[firehol_level2](#firehol_level2)|26368|38001|259|0.6%|0.0%|
[openbl_60d](#openbl_60d)|7208|7208|251|3.4%|0.0%|
[zeus](#zeus)|232|232|229|98.7%|0.0%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|0.0%|
[blocklist_de](#blocklist_de)|32230|32230|195|0.6%|0.0%|
[openbl_30d](#openbl_30d)|2882|2882|127|4.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|124|3.7%|0.0%|
[shunlist](#shunlist)|1231|1231|102|8.2%|0.0%|
[et_compromised](#et_compromised)|1678|1678|101|6.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|101|5.8%|0.0%|
[feodo](#feodo)|102|102|99|97.0%|0.0%|
[nixspam](#nixspam)|39998|39998|89|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|81|1.1%|0.0%|
[openbl_7d](#openbl_7d)|824|824|46|5.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|41|1.1%|0.0%|
[sslbl](#sslbl)|380|380|37|9.7%|0.0%|
[php_commenters](#php_commenters)|385|385|30|7.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|22|0.1%|0.0%|
[openbl_1d](#openbl_1d)|135|135|16|11.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|16|0.6%|0.0%|
[voipbl](#voipbl)|10507|10919|14|0.1%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|9|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|8|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|6|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[malc0de](#malc0de)|342|342|5|1.4%|0.0%|
[et_tor](#et_tor)|6400|6400|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6418|6418|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6437|6437|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|5|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|5|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[ciarmy](#ciarmy)|445|445|4|0.8%|0.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|1|1.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|178836|178836|5|0.0%|0.9%|
[firehol_level3](#firehol_level3)|107701|9625160|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5089|688943412|1|0.0%|0.1%|
[et_block](#et_block)|999|18343755|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|1|1.0%|0.1%|

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
[firehol_level3](#firehol_level3)|107701|9625160|1654|0.0%|98.5%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|1638|95.4%|97.6%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|1076|0.6%|64.1%|
[openbl_60d](#openbl_60d)|7208|7208|979|13.5%|58.3%|
[openbl_30d](#openbl_30d)|2882|2882|920|31.9%|54.8%|
[firehol_level2](#firehol_level2)|26368|38001|677|1.7%|40.3%|
[blocklist_de](#blocklist_de)|32230|32230|672|2.0%|40.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|663|20.2%|39.5%|
[shunlist](#shunlist)|1231|1231|407|33.0%|24.2%|
[openbl_7d](#openbl_7d)|824|824|311|37.7%|18.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|151|0.0%|8.9%|
[firehol_level1](#firehol_level1)|5089|688943412|102|0.0%|6.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|101|0.0%|6.0%|
[et_block](#et_block)|999|18343755|101|0.0%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|86|0.0%|5.1%|
[dshield](#dshield)|20|5120|60|1.1%|3.5%|
[openbl_1d](#openbl_1d)|135|135|47|34.8%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|46|0.0%|2.7%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|13|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|10|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|6|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|5|0.2%|0.2%|
[nixspam](#nixspam)|39998|39998|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|11630|11854|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|3|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|2|0.0%|0.1%|
[proxz](#proxz)|1080|1080|2|0.1%|0.1%|
[ciarmy](#ciarmy)|445|445|2|0.4%|0.1%|
[xroxy](#xroxy)|2136|2136|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|1|0.6%|0.0%|

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
[firehol_anonymous](#firehol_anonymous)|18108|82117|5979|7.2%|93.4%|
[dm_tor](#dm_tor)|6418|6418|5934|92.4%|92.7%|
[bm_tor](#bm_tor)|6437|6437|5931|92.1%|92.6%|
[firehol_level3](#firehol_level3)|107701|9625160|1121|0.0%|17.5%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|1083|11.2%|16.9%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|645|0.6%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|623|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|518|1.7%|8.0%|
[firehol_level2](#firehol_level2)|26368|38001|361|0.9%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|357|5.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|186|0.0%|2.9%|
[firehol_proxies](#firehol_proxies)|11630|11854|168|1.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|166|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|165|44.3%|2.5%|
[php_commenters](#php_commenters)|385|385|43|11.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|41|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7208|7208|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|366|366|7|1.9%|0.1%|
[blocklist_de](#blocklist_de)|32230|32230|7|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|6|0.0%|0.0%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[nixspam](#nixspam)|39998|39998|4|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5089|688943412|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|4|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|3|0.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|2|0.0%|0.0%|
[xroxy](#xroxy)|2136|2136|1|0.0%|0.0%|
[shunlist](#shunlist)|1231|1231|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  8 23:15:30 UTC 2015.

The ipset `feodo` has **102** entries, **102** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5089|688943412|102|0.0%|100.0%|
[et_block](#et_block)|999|18343755|99|0.0%|97.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|79|0.8%|77.4%|
[firehol_level3](#firehol_level3)|107701|9625160|79|0.0%|77.4%|
[sslbl](#sslbl)|380|380|37|9.7%|36.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|10.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|2|0.0%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.9%|

## firehol_anonymous

**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **18108** entries, **82117** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11630|11854|11854|100.0%|14.4%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|7198|100.0%|8.7%|
[bm_tor](#bm_tor)|6437|6437|6437|100.0%|7.8%|
[dm_tor](#dm_tor)|6418|6418|6418|100.0%|7.8%|
[firehol_level3](#firehol_level3)|107701|9625160|6293|0.0%|7.6%|
[et_tor](#et_tor)|6400|6400|5979|93.4%|7.2%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|5765|6.2%|7.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3415|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2875|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2834|0.0%|3.4%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|2824|9.6%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|2617|100.0%|3.1%|
[xroxy](#xroxy)|2136|2136|2136|100.0%|2.6%|
[proxyrss](#proxyrss)|1501|1501|1501|100.0%|1.8%|
[firehol_level2](#firehol_level2)|26368|38001|1390|3.6%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|1157|12.0%|1.4%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|1101|15.4%|1.3%|
[proxz](#proxz)|1080|1080|1080|100.0%|1.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.8%|
[blocklist_de](#blocklist_de)|32230|32230|597|1.8%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|511|14.5%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|0.4%|
[nixspam](#nixspam)|39998|39998|118|0.2%|0.1%|
[php_dictionary](#php_dictionary)|630|630|82|13.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|79|0.4%|0.0%|
[voipbl](#voipbl)|10507|10919|78|0.7%|0.0%|
[php_commenters](#php_commenters)|385|385|72|18.7%|0.0%|
[php_spammers](#php_spammers)|622|622|69|11.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|54|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|28|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7208|7208|23|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|11|3.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|11|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|10|0.1%|0.0%|
[firehol_level1](#firehol_level1)|5089|688943412|9|0.0%|0.0%|
[et_block](#et_block)|999|18343755|8|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|5|3.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|5|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1678|1678|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|3|0.1%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1231|1231|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2882|2882|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## firehol_level1

**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5089** entries, **688943412** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3720|670264216|670264216|100.0%|97.2%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[et_block](#et_block)|999|18343755|18340164|99.9%|2.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|18338560|100.0%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8864386|2.5%|1.2%|
[firehol_level3](#firehol_level3)|107701|9625160|7499668|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7497728|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4637284|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2545425|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|4336|2.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1931|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1101|1.1%|0.0%|
[sslbl](#sslbl)|380|380|380|100.0%|0.0%|
[voipbl](#voipbl)|10507|10919|333|3.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|322|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|298|3.0%|0.0%|
[openbl_60d](#openbl_60d)|7208|7208|274|3.8%|0.0%|
[firehol_level2](#firehol_level2)|26368|38001|271|0.7%|0.0%|
[zeus](#zeus)|232|232|232|100.0%|0.0%|
[blocklist_de](#blocklist_de)|32230|32230|206|0.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|0.0%|
[shunlist](#shunlist)|1231|1231|178|14.4%|0.0%|
[openbl_30d](#openbl_30d)|2882|2882|142|4.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|125|3.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|103|6.0%|0.0%|
[feodo](#feodo)|102|102|102|100.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|102|6.0%|0.0%|
[nixspam](#nixspam)|39998|39998|91|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|81|1.1%|0.0%|
[openbl_7d](#openbl_7d)|824|824|46|5.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|44|1.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|38|2.9%|0.0%|
[php_commenters](#php_commenters)|385|385|37|9.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|24|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[openbl_1d](#openbl_1d)|135|135|16|11.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|16|0.6%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|12|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|9|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|9|5.5%|0.0%|
[malc0de](#malc0de)|342|342|7|2.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|6|0.9%|0.0%|
[dm_tor](#dm_tor)|6418|6418|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|5|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[ciarmy](#ciarmy)|445|445|4|0.8%|0.0%|
[bm_tor](#bm_tor)|6437|6437|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|3|0.8%|0.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[virbl](#virbl)|13|13|1|7.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|1|0.8%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|1|1.0%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **26368** entries, **38001** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|32230|32230|32230|100.0%|84.8%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|19516|99.8%|51.3%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|16804|100.0%|44.2%|
[firehol_level3](#firehol_level3)|107701|9625160|7219|0.0%|18.9%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|7133|100.0%|18.7%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|5726|6.2%|15.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|5481|100.0%|14.4%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|4861|16.6%|12.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4230|0.0%|11.1%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|3490|99.6%|9.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|3243|98.9%|8.5%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|2418|99.3%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1759|0.0%|4.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1686|0.0%|4.4%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|1539|0.8%|4.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|1390|1.6%|3.6%|
[firehol_proxies](#firehol_proxies)|11630|11854|1177|9.9%|3.0%|
[openbl_60d](#openbl_60d)|7208|7208|1173|16.2%|3.0%|
[nixspam](#nixspam)|39998|39998|1067|2.6%|2.8%|
[openbl_30d](#openbl_30d)|2882|2882|895|31.0%|2.3%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|743|43.2%|1.9%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|707|9.8%|1.8%|
[et_compromised](#et_compromised)|1678|1678|677|40.3%|1.7%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|656|6.8%|1.7%|
[shunlist](#shunlist)|1231|1231|441|35.8%|1.1%|
[openbl_7d](#openbl_7d)|824|824|440|53.3%|1.1%|
[proxyrss](#proxyrss)|1501|1501|397|26.4%|1.0%|
[xroxy](#xroxy)|2136|2136|368|17.2%|0.9%|
[et_tor](#et_tor)|6400|6400|361|5.6%|0.9%|
[dm_tor](#dm_tor)|6418|6418|352|5.4%|0.9%|
[bm_tor](#bm_tor)|6437|6437|352|5.4%|0.9%|
[firehol_level1](#firehol_level1)|5089|688943412|271|0.0%|0.7%|
[et_block](#et_block)|999|18343755|259|0.0%|0.6%|
[proxz](#proxz)|1080|1080|253|23.4%|0.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|246|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|189|7.2%|0.4%|
[php_commenters](#php_commenters)|385|385|182|47.2%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|163|100.0%|0.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|156|41.9%|0.4%|
[openbl_1d](#openbl_1d)|135|135|135|100.0%|0.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|133|133|128|96.2%|0.3%|
[php_dictionary](#php_dictionary)|630|630|95|15.0%|0.2%|
[php_spammers](#php_spammers)|622|622|94|15.1%|0.2%|
[dshield](#dshield)|20|5120|88|1.7%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|72|78.2%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|65|0.0%|0.1%|
[php_harvesters](#php_harvesters)|366|366|57|15.5%|0.1%|
[ciarmy](#ciarmy)|445|445|38|8.5%|0.0%|
[voipbl](#voipbl)|10507|10919|37|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|14|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|10|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[zeus_badips](#zeus_badips)|203|203|2|0.9%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **107701** entries, **9625160** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5089|688943412|7499668|1.0%|77.9%|
[et_block](#et_block)|999|18343755|6933327|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6933026|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537307|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919952|0.1%|9.5%|
[fullbogons](#fullbogons)|3720|670264216|566182|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161472|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|92247|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|29205|99.7%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|9624|100.0%|0.0%|
[firehol_level2](#firehol_level2)|26368|38001|7219|18.9%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|6293|7.6%|0.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|5190|43.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|5180|2.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|4425|62.0%|0.0%|
[blocklist_de](#blocklist_de)|32230|32230|3891|12.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|3450|47.9%|0.0%|
[openbl_60d](#openbl_60d)|7208|7208|3012|41.7%|0.0%|
[openbl_30d](#openbl_30d)|2882|2882|2882|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|2168|61.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|1716|100.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1654|98.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|1485|56.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[xroxy](#xroxy)|2136|2136|1273|59.5%|0.0%|
[shunlist](#shunlist)|1231|1231|1231|100.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1121|17.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|1095|33.3%|0.0%|
[dm_tor](#dm_tor)|6418|6418|1085|16.9%|0.0%|
[bm_tor](#bm_tor)|6437|6437|1085|16.8%|0.0%|
[openbl_7d](#openbl_7d)|824|824|824|100.0%|0.0%|
[nixspam](#nixspam)|39998|39998|777|1.9%|0.0%|
[proxyrss](#proxyrss)|1501|1501|667|44.4%|0.0%|
[proxz](#proxz)|1080|1080|647|59.9%|0.0%|
[php_dictionary](#php_dictionary)|630|630|630|100.0%|0.0%|
[php_spammers](#php_spammers)|622|622|622|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|494|2.5%|0.0%|
[ciarmy](#ciarmy)|445|445|445|100.0%|0.0%|
[php_commenters](#php_commenters)|385|385|385|100.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|366|100.0%|0.0%|
[dshield](#dshield)|20|5120|363|7.0%|0.0%|
[malc0de](#malc0de)|342|342|342|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|282|1.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|233|62.6%|0.0%|
[zeus](#zeus)|232|232|203|87.5%|0.0%|
[zeus_badips](#zeus_badips)|203|203|181|89.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|148|90.7%|0.0%|
[openbl_1d](#openbl_1d)|135|135|132|97.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|123|100.0%|0.0%|
[sslbl](#sslbl)|380|380|95|25.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|90|0.0%|0.0%|
[feodo](#feodo)|102|102|79|77.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|78|1.4%|0.0%|
[voipbl](#voipbl)|10507|10919|59|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|59|2.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|25|3.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|25|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|133|133|14|10.5%|0.0%|
[virbl](#virbl)|13|13|13|100.0%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|3|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|2|2.1%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **11630** entries, **11854** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18108|82117|11854|14.4%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|7198|100.0%|60.7%|
[firehol_level3](#firehol_level3)|107701|9625160|5190|0.0%|43.7%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|5126|5.5%|43.2%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|2617|100.0%|22.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|2433|8.3%|20.5%|
[xroxy](#xroxy)|2136|2136|2136|100.0%|18.0%|
[proxyrss](#proxyrss)|1501|1501|1501|100.0%|12.6%|
[firehol_level2](#firehol_level2)|26368|38001|1177|3.0%|9.9%|
[proxz](#proxz)|1080|1080|1080|100.0%|9.1%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|889|12.4%|7.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.5%|
[blocklist_de](#blocklist_de)|32230|32230|593|1.8%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|509|14.5%|4.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|486|0.0%|4.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|371|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|268|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|260|2.7%|2.1%|
[et_tor](#et_tor)|6400|6400|168|2.6%|1.4%|
[dm_tor](#dm_tor)|6418|6418|166|2.5%|1.4%|
[bm_tor](#bm_tor)|6437|6437|166|2.5%|1.4%|
[nixspam](#nixspam)|39998|39998|112|0.2%|0.9%|
[php_dictionary](#php_dictionary)|630|630|81|12.8%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|79|0.4%|0.6%|
[php_spammers](#php_spammers)|622|622|67|10.7%|0.5%|
[php_commenters](#php_commenters)|385|385|66|17.1%|0.5%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|32|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7208|7208|18|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|10|2.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|9|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|8|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|5|3.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|5|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[firehol_level1](#firehol_level1)|5089|688943412|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|3|0.1%|0.0%|
[et_block](#et_block)|999|18343755|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|3|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[shunlist](#shunlist)|1231|1231|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5089|688943412|670264216|97.2%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4235823|3.0%|0.6%|
[firehol_level3](#firehol_level3)|107701|9625160|566182|5.8%|0.0%|
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
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[ciarmy](#ciarmy)|445|445|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|107701|9625160|25|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5089|688943412|18|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|15|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|14|0.0%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[nixspam](#nixspam)|39998|39998|10|0.0%|0.0%|
[firehol_level2](#firehol_level2)|26368|38001|10|0.0%|0.0%|
[blocklist_de](#blocklist_de)|32230|32230|10|0.0%|0.0%|
[et_block](#et_block)|999|18343755|9|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|6|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|4|0.0%|0.0%|
[xroxy](#xroxy)|2136|2136|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|630|630|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|3|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|1|0.0%|0.0%|
[proxz](#proxz)|1080|1080|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|107701|9625160|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5089|688943412|7497728|1.0%|81.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6932480|37.8%|75.5%|
[et_block](#et_block)|999|18343755|6932480|37.7%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3720|670264216|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|732|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|518|0.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|158|0.5%|0.0%|
[nixspam](#nixspam)|39998|39998|88|0.2%|0.0%|
[firehol_level2](#firehol_level2)|26368|38001|65|0.1%|0.0%|
[blocklist_de](#blocklist_de)|32230|32230|44|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|34|0.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|27|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|7208|7208|17|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|12|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2882|2882|12|0.4%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[zeus](#zeus)|232|232|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|6|0.1%|0.0%|
[openbl_7d](#openbl_7d)|824|824|5|0.6%|0.0%|
[et_compromised](#et_compromised)|1678|1678|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|5|0.2%|0.0%|
[php_dictionary](#php_dictionary)|630|630|4|0.6%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6418|6418|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6437|6437|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|4|0.0%|0.0%|
[shunlist](#shunlist)|1231|1231|3|0.2%|0.0%|
[php_spammers](#php_spammers)|622|622|3|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|3|1.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|3|0.1%|0.0%|
[openbl_1d](#openbl_1d)|135|135|2|1.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|2|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
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
[firehol_level1](#firehol_level1)|5089|688943412|2545425|0.3%|0.3%|
[et_block](#et_block)|999|18343755|2272541|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|107701|9625160|919952|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3720|670264216|239993|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|4131|2.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|3415|4.1%|0.0%|
[firehol_level2](#firehol_level2)|26368|38001|1686|4.4%|0.0%|
[blocklist_de](#blocklist_de)|32230|32230|1573|4.8%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1511|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|1419|7.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|1327|7.8%|0.0%|
[nixspam](#nixspam)|39998|39998|665|1.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|558|1.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[voipbl](#voipbl)|10507|10919|299|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|268|2.2%|0.0%|
[openbl_60d](#openbl_60d)|7208|7208|167|2.3%|0.0%|
[et_tor](#et_tor)|6400|6400|166|2.5%|0.0%|
[bm_tor](#bm_tor)|6437|6437|166|2.5%|0.0%|
[dm_tor](#dm_tor)|6418|6418|165|2.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|140|1.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|123|1.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|107|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|79|3.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|74|2.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2882|2882|63|2.1%|0.0%|
[xroxy](#xroxy)|2136|2136|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|51|2.9%|0.0%|
[et_compromised](#et_compromised)|1678|1678|46|2.7%|0.0%|
[et_botcc](#et_botcc)|509|509|40|7.8%|0.0%|
[proxyrss](#proxyrss)|1501|1501|38|2.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|38|0.6%|0.0%|
[proxz](#proxz)|1080|1080|37|3.4%|0.0%|
[ciarmy](#ciarmy)|445|445|35|7.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|31|1.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|29|0.8%|0.0%|
[shunlist](#shunlist)|1231|1231|25|2.0%|0.0%|
[openbl_7d](#openbl_7d)|824|824|19|2.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[php_harvesters](#php_harvesters)|366|366|11|3.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|11|1.7%|0.0%|
[malc0de](#malc0de)|342|342|11|3.2%|0.0%|
[php_commenters](#php_commenters)|385|385|10|2.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|10|8.1%|0.0%|
[php_spammers](#php_spammers)|622|622|9|1.4%|0.0%|
[zeus](#zeus)|232|232|6|2.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|6|6.5%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|4|1.9%|0.0%|
[openbl_1d](#openbl_1d)|135|135|4|2.9%|0.0%|
[sslbl](#sslbl)|380|380|3|0.7%|0.0%|
[feodo](#feodo)|102|102|3|2.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|133|133|1|0.7%|0.0%|

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
[firehol_level1](#firehol_level1)|5089|688943412|8864386|1.2%|2.5%|
[et_block](#et_block)|999|18343755|8533288|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|107701|9625160|2537307|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3720|670264216|249087|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|6255|3.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|2875|3.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2489|2.6%|0.0%|
[firehol_level2](#firehol_level2)|26368|38001|1759|4.6%|0.0%|
[blocklist_de](#blocklist_de)|32230|32230|1604|4.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|1247|6.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|1098|6.5%|0.0%|
[nixspam](#nixspam)|39998|39998|864|2.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|853|2.9%|0.0%|
[voipbl](#voipbl)|10507|10919|434|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|371|3.1%|0.0%|
[openbl_60d](#openbl_60d)|7208|7208|326|4.5%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|210|2.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|199|2.7%|0.0%|
[et_tor](#et_tor)|6400|6400|186|2.9%|0.0%|
[dm_tor](#dm_tor)|6418|6418|183|2.8%|0.0%|
[bm_tor](#bm_tor)|6437|6437|183|2.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|163|1.6%|0.0%|
[openbl_30d](#openbl_30d)|2882|2882|151|5.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|144|4.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|126|3.5%|0.0%|
[xroxy](#xroxy)|2136|2136|104|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|101|3.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|90|5.2%|0.0%|
[et_compromised](#et_compromised)|1678|1678|86|5.1%|0.0%|
[shunlist](#shunlist)|1231|1231|68|5.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|63|1.1%|0.0%|
[proxyrss](#proxyrss)|1501|1501|54|3.5%|0.0%|
[php_spammers](#php_spammers)|622|622|51|8.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|51|2.0%|0.0%|
[openbl_7d](#openbl_7d)|824|824|47|5.7%|0.0%|
[ciarmy](#ciarmy)|445|445|47|10.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[proxz](#proxz)|1080|1080|42|3.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[php_dictionary](#php_dictionary)|630|630|22|3.4%|0.0%|
[et_botcc](#et_botcc)|509|509|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[malc0de](#malc0de)|342|342|20|5.8%|0.0%|
[php_commenters](#php_commenters)|385|385|15|3.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|133|133|10|7.5%|0.0%|
[zeus](#zeus)|232|232|9|3.8%|0.0%|
[php_harvesters](#php_harvesters)|366|366|9|2.4%|0.0%|
[openbl_1d](#openbl_1d)|135|135|9|6.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|8|3.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|8|8.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|6|3.6%|0.0%|
[sslbl](#sslbl)|380|380|4|1.0%|0.0%|
[feodo](#feodo)|102|102|3|2.9%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|2|1.6%|0.0%|

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
[firehol_level1](#firehol_level1)|5089|688943412|4637284|0.6%|3.3%|
[fullbogons](#fullbogons)|3720|670264216|4235823|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|107701|9625160|161472|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|999|18343755|130394|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|13855|7.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|5743|6.2%|0.0%|
[firehol_level2](#firehol_level2)|26368|38001|4230|11.1%|0.0%|
[blocklist_de](#blocklist_de)|32230|32230|3775|11.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|2834|3.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|2650|13.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|2492|14.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1899|6.4%|0.0%|
[voipbl](#voipbl)|10507|10919|1600|14.6%|0.0%|
[nixspam](#nixspam)|39998|39998|1305|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7208|7208|742|10.2%|0.0%|
[et_tor](#et_tor)|6400|6400|623|9.7%|0.0%|
[dm_tor](#dm_tor)|6418|6418|619|9.6%|0.0%|
[bm_tor](#bm_tor)|6437|6437|617|9.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|513|7.1%|0.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|486|4.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|459|13.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|397|7.2%|0.0%|
[openbl_30d](#openbl_30d)|2882|2882|292|10.1%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|254|2.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|236|6.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|201|2.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|201|8.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|153|8.9%|0.0%|
[et_compromised](#et_compromised)|1678|1678|151|8.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[shunlist](#shunlist)|1231|1231|114|9.2%|0.0%|
[openbl_7d](#openbl_7d)|824|824|111|13.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[xroxy](#xroxy)|2136|2136|104|4.8%|0.0%|
[proxz](#proxz)|1080|1080|93|8.6%|0.0%|
[ciarmy](#ciarmy)|445|445|86|19.3%|0.0%|
[et_botcc](#et_botcc)|509|509|80|15.7%|0.0%|
[proxyrss](#proxyrss)|1501|1501|56|3.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|54|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[malc0de](#malc0de)|342|342|48|14.0%|0.0%|
[php_spammers](#php_spammers)|622|622|37|5.9%|0.0%|
[php_dictionary](#php_dictionary)|630|630|33|5.2%|0.0%|
[sslbl](#sslbl)|380|380|30|7.8%|0.0%|
[php_commenters](#php_commenters)|385|385|24|6.2%|0.0%|
[php_harvesters](#php_harvesters)|366|366|19|5.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|16|9.8%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|16|17.3%|0.0%|
[zeus](#zeus)|232|232|14|6.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|133|133|13|9.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|12|9.7%|0.0%|
[feodo](#feodo)|102|102|11|10.7%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[openbl_1d](#openbl_1d)|135|135|10|7.4%|0.0%|
[virbl](#virbl)|13|13|1|7.6%|0.0%|
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
[firehol_proxies](#firehol_proxies)|11630|11854|663|5.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|663|0.8%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|107701|9625160|25|0.0%|3.7%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|20|0.0%|3.0%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|14|0.1%|2.1%|
[xroxy](#xroxy)|2136|2136|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|13|0.0%|1.9%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1501|1501|8|0.5%|1.2%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|7|0.2%|1.0%|
[proxz](#proxz)|1080|1080|6|0.5%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|5|0.0%|0.7%|
[firehol_level2](#firehol_level2)|26368|38001|5|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.3%|
[nixspam](#nixspam)|39998|39998|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5089|688943412|2|0.0%|0.3%|
[et_block](#et_block)|999|18343755|2|0.0%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|2|0.0%|0.3%|
[blocklist_de](#blocklist_de)|32230|32230|2|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|630|630|1|0.1%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|1|0.0%|0.1%|

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
[firehol_level3](#firehol_level3)|107701|9625160|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5089|688943412|1931|0.0%|0.5%|
[et_block](#et_block)|999|18343755|1041|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3720|670264216|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|46|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|28|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|22|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6418|6418|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6437|6437|22|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[nixspam](#nixspam)|39998|39998|16|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|15|0.1%|0.0%|
[firehol_level2](#firehol_level2)|26368|38001|14|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|9|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7208|7208|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[blocklist_de](#blocklist_de)|32230|32230|5|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2882|2882|4|0.1%|0.0%|
[malc0de](#malc0de)|342|342|3|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|3|0.0%|0.0%|
[proxyrss](#proxyrss)|1501|1501|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|2|2.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[xroxy](#xroxy)|2136|2136|1|0.0%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|1|0.0%|0.0%|
[proxz](#proxz)|1080|1080|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|630|630|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[feodo](#feodo)|102|102|1|0.9%|0.0%|
[ciarmy](#ciarmy)|445|445|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|107701|9625160|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5089|688943412|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3720|670264216|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|10|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.4%|
[et_block](#et_block)|999|18343755|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|11630|11854|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7208|7208|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2882|2882|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[firehol_level2](#firehol_level2)|26368|38001|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|824|824|1|0.1%|0.0%|
[nixspam](#nixspam)|39998|39998|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|32230|32230|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|107701|9625160|342|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|48|0.0%|14.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|20|0.0%|5.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.2%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|10|0.0%|2.9%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|8|6.5%|2.3%|
[firehol_level1](#firehol_level1)|5089|688943412|7|0.0%|2.0%|
[et_block](#et_block)|999|18343755|5|0.0%|1.4%|
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
[firehol_level3](#firehol_level3)|107701|9625160|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5089|688943412|38|0.0%|2.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|29|0.0%|2.2%|
[et_block](#et_block)|999|18343755|29|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|28|0.2%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3720|670264216|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|7|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|4|0.0%|0.3%|
[malc0de](#malc0de)|342|342|4|1.1%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[nixspam](#nixspam)|39998|39998|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|1|0.8%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Mon Jun  8 21:00:03 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11630|11854|372|3.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|372|0.4%|100.0%|
[firehol_level3](#firehol_level3)|107701|9625160|233|0.0%|62.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|232|0.2%|62.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|190|0.6%|51.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|172|1.7%|46.2%|
[et_tor](#et_tor)|6400|6400|165|2.5%|44.3%|
[dm_tor](#dm_tor)|6418|6418|163|2.5%|43.8%|
[bm_tor](#bm_tor)|6437|6437|163|2.5%|43.8%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|156|2.1%|41.9%|
[firehol_level2](#firehol_level2)|26368|38001|156|0.4%|41.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|125|0.0%|33.6%|
[php_commenters](#php_commenters)|385|385|40|10.3%|10.7%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7208|7208|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|366|366|6|1.6%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|4|0.0%|1.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|1.0%|
[php_dictionary](#php_dictionary)|630|630|4|0.6%|1.0%|
[xroxy](#xroxy)|2136|2136|1|0.0%|0.2%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.2%|
[shunlist](#shunlist)|1231|1231|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|1|0.0%|0.2%|
[nixspam](#nixspam)|39998|39998|1|0.0%|0.2%|
[et_block](#et_block)|999|18343755|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|32230|32230|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Mon Jun  8 23:30:03 UTC 2015.

The ipset `nixspam` has **39998** entries, **39998** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1305|0.0%|3.2%|
[firehol_level2](#firehol_level2)|26368|38001|1067|2.8%|2.6%|
[blocklist_de](#blocklist_de)|32230|32230|1047|3.2%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|962|4.9%|2.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|864|0.0%|2.1%|
[firehol_level3](#firehol_level3)|107701|9625160|777|0.0%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|665|0.0%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|480|4.9%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|213|0.2%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|119|0.4%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|118|0.1%|0.2%|
[firehol_proxies](#firehol_proxies)|11630|11854|112|0.9%|0.2%|
[php_dictionary](#php_dictionary)|630|630|103|16.3%|0.2%|
[firehol_level1](#firehol_level1)|5089|688943412|91|0.0%|0.2%|
[et_block](#et_block)|999|18343755|89|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|88|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|88|0.0%|0.2%|
[php_spammers](#php_spammers)|622|622|84|13.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|77|1.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|67|0.9%|0.1%|
[xroxy](#xroxy)|2136|2136|54|2.5%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|47|1.3%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|45|0.0%|0.1%|
[proxz](#proxz)|1080|1080|34|3.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|34|0.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|34|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|21|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|16|0.0%|0.0%|
[proxyrss](#proxyrss)|1501|1501|13|0.8%|0.0%|
[php_harvesters](#php_harvesters)|366|366|11|3.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|10|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|10|0.0%|0.0%|
[php_commenters](#php_commenters)|385|385|8|2.0%|0.0%|
[dm_tor](#dm_tor)|6418|6418|6|0.0%|0.0%|
[bm_tor](#bm_tor)|6437|6437|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7208|7208|5|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|3|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|3|1.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[shunlist](#shunlist)|1231|1231|2|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2882|2882|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Mon Jun  8 23:12:00 UTC 2015.

The ipset `openbl_1d` has **135** entries, **135** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26368|38001|135|0.3%|100.0%|
[firehol_level3](#firehol_level3)|107701|9625160|132|0.0%|97.7%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|131|0.0%|97.0%|
[openbl_60d](#openbl_60d)|7208|7208|130|1.8%|96.2%|
[openbl_30d](#openbl_30d)|2882|2882|130|4.5%|96.2%|
[openbl_7d](#openbl_7d)|824|824|127|15.4%|94.0%|
[blocklist_de](#blocklist_de)|32230|32230|107|0.3%|79.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|106|3.2%|78.5%|
[shunlist](#shunlist)|1231|1231|61|4.9%|45.1%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|56|3.2%|41.4%|
[et_compromised](#et_compromised)|1678|1678|47|2.8%|34.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|18|11.0%|13.3%|
[firehol_level1](#firehol_level1)|5089|688943412|16|0.0%|11.8%|
[et_block](#et_block)|999|18343755|16|0.0%|11.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|13|0.0%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|6.6%|
[dshield](#dshield)|20|5120|7|0.1%|5.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|2.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|1.4%|
[ciarmy](#ciarmy)|445|445|1|0.2%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|1|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|1|0.0%|0.7%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Mon Jun  8 20:07:00 UTC 2015.

The ipset `openbl_30d` has **2882** entries, **2882** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7208|7208|2882|39.9%|100.0%|
[firehol_level3](#firehol_level3)|107701|9625160|2882|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|2868|1.6%|99.5%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|933|54.3%|32.3%|
[et_compromised](#et_compromised)|1678|1678|920|54.8%|31.9%|
[firehol_level2](#firehol_level2)|26368|38001|895|2.3%|31.0%|
[blocklist_de](#blocklist_de)|32230|32230|868|2.6%|30.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|827|25.2%|28.6%|
[openbl_7d](#openbl_7d)|824|824|824|100.0%|28.5%|
[shunlist](#shunlist)|1231|1231|518|42.0%|17.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|292|0.0%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|151|0.0%|5.2%|
[firehol_level1](#firehol_level1)|5089|688943412|142|0.0%|4.9%|
[openbl_1d](#openbl_1d)|135|135|130|96.2%|4.5%|
[et_block](#et_block)|999|18343755|127|0.0%|4.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|120|0.0%|4.1%|
[dshield](#dshield)|20|5120|88|1.7%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|63|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|39|0.1%|1.3%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|30|1.2%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|25|15.3%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|6|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|3|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|2|0.0%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[nixspam](#nixspam)|39998|39998|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|1|0.0%|0.0%|
[ciarmy](#ciarmy)|445|445|1|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|133|133|1|0.7%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Mon Jun  8 20:07:00 UTC 2015.

The ipset `openbl_60d` has **7208** entries, **7208** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178836|178836|7188|4.0%|99.7%|
[firehol_level3](#firehol_level3)|107701|9625160|3012|0.0%|41.7%|
[openbl_30d](#openbl_30d)|2882|2882|2882|100.0%|39.9%|
[firehol_level2](#firehol_level2)|26368|38001|1173|3.0%|16.2%|
[blocklist_de](#blocklist_de)|32230|32230|1127|3.4%|15.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|1063|32.4%|14.7%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|992|57.8%|13.7%|
[et_compromised](#et_compromised)|1678|1678|979|58.3%|13.5%|
[openbl_7d](#openbl_7d)|824|824|824|100.0%|11.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|742|0.0%|10.2%|
[shunlist](#shunlist)|1231|1231|545|44.2%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|326|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5089|688943412|274|0.0%|3.8%|
[et_block](#et_block)|999|18343755|251|0.0%|3.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|239|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|167|0.0%|2.3%|
[openbl_1d](#openbl_1d)|135|135|130|96.2%|1.8%|
[dshield](#dshield)|20|5120|100|1.9%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|54|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|47|0.2%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|35|1.4%|0.4%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|28|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|26|15.9%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|24|0.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|23|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|20|0.2%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6418|6418|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6437|6437|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[firehol_proxies](#firehol_proxies)|11630|11854|18|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|17|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|15|0.4%|0.2%|
[php_commenters](#php_commenters)|385|385|10|2.5%|0.1%|
[voipbl](#voipbl)|10507|10919|8|0.0%|0.1%|
[nixspam](#nixspam)|39998|39998|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|133|133|2|1.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[ciarmy](#ciarmy)|445|445|1|0.2%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Mon Jun  8 20:07:00 UTC 2015.

The ipset `openbl_7d` has **824** entries, **824** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7208|7208|824|11.4%|100.0%|
[openbl_30d](#openbl_30d)|2882|2882|824|28.5%|100.0%|
[firehol_level3](#firehol_level3)|107701|9625160|824|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|819|0.4%|99.3%|
[firehol_level2](#firehol_level2)|26368|38001|440|1.1%|53.3%|
[blocklist_de](#blocklist_de)|32230|32230|414|1.2%|50.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|402|12.2%|48.7%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|319|18.5%|38.7%|
[et_compromised](#et_compromised)|1678|1678|311|18.5%|37.7%|
[shunlist](#shunlist)|1231|1231|214|17.3%|25.9%|
[openbl_1d](#openbl_1d)|135|135|127|94.0%|15.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|111|0.0%|13.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|47|0.0%|5.7%|
[firehol_level1](#firehol_level1)|5089|688943412|46|0.0%|5.5%|
[et_block](#et_block)|999|18343755|46|0.0%|5.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|42|0.0%|5.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|24|14.7%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|19|0.0%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|12|0.0%|1.4%|
[dshield](#dshield)|20|5120|11|0.2%|1.3%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|11|0.4%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|3|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|2|0.0%|0.2%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.1%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ciarmy](#ciarmy)|445|445|1|0.2%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|133|133|1|0.7%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  8 23:15:27 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5089|688943412|13|0.0%|100.0%|
[et_block](#et_block)|999|18343755|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|107701|9625160|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Mon Jun  8 22:56:29 UTC 2015.

The ipset `php_commenters` has **385** entries, **385** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107701|9625160|385|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|287|0.3%|74.5%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|215|0.7%|55.8%|
[firehol_level2](#firehol_level2)|26368|38001|182|0.4%|47.2%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|159|2.2%|41.2%|
[blocklist_de](#blocklist_de)|32230|32230|94|0.2%|24.4%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|76|2.1%|19.7%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|72|0.0%|18.7%|
[firehol_proxies](#firehol_proxies)|11630|11854|66|0.5%|17.1%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|51|0.5%|13.2%|
[et_tor](#et_tor)|6400|6400|43|0.6%|11.1%|
[dm_tor](#dm_tor)|6418|6418|43|0.6%|11.1%|
[bm_tor](#bm_tor)|6437|6437|43|0.6%|11.1%|
[php_spammers](#php_spammers)|622|622|42|6.7%|10.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|41|25.1%|10.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|40|10.7%|10.3%|
[firehol_level1](#firehol_level1)|5089|688943412|37|0.0%|9.6%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|31|0.1%|8.0%|
[et_block](#et_block)|999|18343755|30|0.0%|7.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|29|0.0%|7.5%|
[php_dictionary](#php_dictionary)|630|630|26|4.1%|6.7%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|25|0.1%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|24|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|23|0.3%|5.9%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|17|0.0%|4.4%|
[php_harvesters](#php_harvesters)|366|366|15|4.0%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|15|0.0%|3.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|11|0.2%|2.8%|
[openbl_60d](#openbl_60d)|7208|7208|10|0.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.5%|
[xroxy](#xroxy)|2136|2136|8|0.3%|2.0%|
[nixspam](#nixspam)|39998|39998|8|0.0%|2.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|1.8%|
[proxz](#proxz)|1080|1080|7|0.6%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|5|0.1%|1.2%|
[proxyrss](#proxyrss)|1501|1501|4|0.2%|1.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.2%|
[zeus](#zeus)|232|232|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|824|824|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2882|2882|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Mon Jun  8 22:56:31 UTC 2015.

The ipset `php_dictionary` has **630** entries, **630** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107701|9625160|630|0.0%|100.0%|
[php_spammers](#php_spammers)|622|622|243|39.0%|38.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|117|0.1%|18.5%|
[nixspam](#nixspam)|39998|39998|103|0.2%|16.3%|
[firehol_level2](#firehol_level2)|26368|38001|95|0.2%|15.0%|
[blocklist_de](#blocklist_de)|32230|32230|89|0.2%|14.1%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|85|0.8%|13.4%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|82|0.0%|13.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|81|0.6%|12.8%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|79|0.2%|12.5%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|59|0.3%|9.3%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|53|0.7%|8.4%|
[xroxy](#xroxy)|2136|2136|38|1.7%|6.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|33|0.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|32|0.4%|5.0%|
[php_commenters](#php_commenters)|385|385|26|6.7%|4.1%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|25|0.7%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|22|0.0%|3.4%|
[proxz](#proxz)|1080|1080|21|1.9%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|1.7%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|8|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.9%|
[firehol_level1](#firehol_level1)|5089|688943412|6|0.0%|0.9%|
[et_block](#et_block)|999|18343755|6|0.0%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|5|0.0%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|5|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|4|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|4|2.4%|0.6%|
[proxyrss](#proxyrss)|1501|1501|3|0.1%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.4%|
[dm_tor](#dm_tor)|6418|6418|3|0.0%|0.4%|
[bm_tor](#bm_tor)|6437|6437|3|0.0%|0.4%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|1|0.0%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Mon Jun  8 22:56:28 UTC 2015.

The ipset `php_harvesters` has **366** entries, **366** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107701|9625160|366|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|80|0.0%|21.8%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|60|0.2%|16.3%|
[firehol_level2](#firehol_level2)|26368|38001|57|0.1%|15.5%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|43|0.6%|11.7%|
[blocklist_de](#blocklist_de)|32230|32230|42|0.1%|11.4%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|31|0.8%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|19|0.0%|5.1%|
[php_commenters](#php_commenters)|385|385|15|3.8%|4.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|14|0.1%|3.8%|
[nixspam](#nixspam)|39998|39998|11|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|11|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|11|0.0%|3.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|10|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.4%|
[et_tor](#et_tor)|6400|6400|7|0.1%|1.9%|
[dm_tor](#dm_tor)|6418|6418|7|0.1%|1.9%|
[bm_tor](#bm_tor)|6437|6437|7|0.1%|1.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|133|133|6|4.5%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|4|0.0%|1.0%|
[firehol_level1](#firehol_level1)|5089|688943412|3|0.0%|0.8%|
[xroxy](#xroxy)|2136|2136|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|2|0.0%|0.5%|
[php_spammers](#php_spammers)|622|622|2|0.3%|0.5%|
[php_dictionary](#php_dictionary)|630|630|2|0.3%|0.5%|
[openbl_60d](#openbl_60d)|7208|7208|2|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|2|1.2%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.2%|
[proxyrss](#proxyrss)|1501|1501|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[et_block](#et_block)|999|18343755|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Mon Jun  8 22:56:28 UTC 2015.

The ipset `php_spammers` has **622** entries, **622** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107701|9625160|622|0.0%|100.0%|
[php_dictionary](#php_dictionary)|630|630|243|38.5%|39.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|127|0.1%|20.4%|
[firehol_level2](#firehol_level2)|26368|38001|94|0.2%|15.1%|
[nixspam](#nixspam)|39998|39998|84|0.2%|13.5%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|82|0.8%|13.1%|
[blocklist_de](#blocklist_de)|32230|32230|81|0.2%|13.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|72|0.2%|11.5%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|69|0.0%|11.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|67|0.5%|10.7%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|52|0.2%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|51|0.0%|8.1%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|45|0.6%|7.2%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|44|0.6%|7.0%|
[php_commenters](#php_commenters)|385|385|42|10.9%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|37|0.0%|5.9%|
[xroxy](#xroxy)|2136|2136|30|1.4%|4.8%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|22|0.6%|3.5%|
[proxz](#proxz)|1080|1080|20|1.8%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|9|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|6|3.6%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|6|0.1%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|6|0.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|5|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[firehol_level1](#firehol_level1)|5089|688943412|4|0.0%|0.6%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.6%|
[et_block](#et_block)|999|18343755|4|0.0%|0.6%|
[dm_tor](#dm_tor)|6418|6418|4|0.0%|0.6%|
[bm_tor](#bm_tor)|6437|6437|4|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|3|0.1%|0.4%|
[proxyrss](#proxyrss)|1501|1501|3|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.3%|
[openbl_7d](#openbl_7d)|824|824|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7208|7208|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2882|2882|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Mon Jun  8 21:21:27 UTC 2015.

The ipset `proxyrss` has **1501** entries, **1501** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11630|11854|1501|12.6%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|1501|1.8%|100.0%|
[firehol_level3](#firehol_level3)|107701|9625160|667|0.0%|44.4%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|666|0.7%|44.3%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|571|7.9%|38.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|516|1.7%|34.3%|
[firehol_level2](#firehol_level2)|26368|38001|397|1.0%|26.4%|
[xroxy](#xroxy)|2136|2136|361|16.9%|24.0%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|344|4.8%|22.9%|
[proxz](#proxz)|1080|1080|241|22.3%|16.0%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|217|8.2%|14.4%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|194|5.5%|12.9%|
[blocklist_de](#blocklist_de)|32230|32230|193|0.5%|12.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|56|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|54|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|38|0.0%|2.5%|
[nixspam](#nixspam)|39998|39998|13|0.0%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|8|1.2%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|4|0.0%|0.2%|
[php_commenters](#php_commenters)|385|385|4|1.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|4|2.4%|0.2%|
[php_spammers](#php_spammers)|622|622|3|0.4%|0.1%|
[php_dictionary](#php_dictionary)|630|630|3|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|2|0.0%|0.1%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Mon Jun  8 21:21:32 UTC 2015.

The ipset `proxz` has **1080** entries, **1080** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11630|11854|1080|9.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|1080|1.3%|100.0%|
[firehol_level3](#firehol_level3)|107701|9625160|647|0.0%|59.9%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|640|0.6%|59.2%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|494|6.8%|45.7%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|461|1.5%|42.6%|
[xroxy](#xroxy)|2136|2136|397|18.5%|36.7%|
[firehol_level2](#firehol_level2)|26368|38001|253|0.6%|23.4%|
[proxyrss](#proxyrss)|1501|1501|241|16.0%|22.3%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|190|2.6%|17.5%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|182|6.9%|16.8%|
[blocklist_de](#blocklist_de)|32230|32230|157|0.4%|14.5%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|140|3.9%|12.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|93|0.0%|8.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|42|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|37|0.0%|3.4%|
[nixspam](#nixspam)|39998|39998|34|0.0%|3.1%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|24|0.2%|2.2%|
[php_dictionary](#php_dictionary)|630|630|21|3.3%|1.9%|
[php_spammers](#php_spammers)|622|622|20|3.2%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|17|0.0%|1.5%|
[php_commenters](#php_commenters)|385|385|7|1.8%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|3|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|3|0.0%|0.2%|
[et_compromised](#et_compromised)|1678|1678|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|1|0.0%|0.0%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Mon Jun  8 22:48:11 UTC 2015.

The ipset `ri_connect_proxies` has **2617** entries, **2617** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11630|11854|2617|22.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|2617|3.1%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1485|1.6%|56.7%|
[firehol_level3](#firehol_level3)|107701|9625160|1485|0.0%|56.7%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|1104|15.3%|42.1%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|635|2.1%|24.2%|
[xroxy](#xroxy)|2136|2136|381|17.8%|14.5%|
[proxyrss](#proxyrss)|1501|1501|217|14.4%|8.2%|
[firehol_level2](#firehol_level2)|26368|38001|189|0.4%|7.2%|
[proxz](#proxz)|1080|1080|182|16.8%|6.9%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|147|2.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|101|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|79|0.0%|3.0%|
[blocklist_de](#blocklist_de)|32230|32230|78|0.2%|2.9%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|75|2.1%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|54|0.0%|2.0%|
[nixspam](#nixspam)|39998|39998|10|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|6|0.0%|0.2%|
[php_commenters](#php_commenters)|385|385|5|1.2%|0.1%|
[php_dictionary](#php_dictionary)|630|630|4|0.6%|0.1%|
[php_spammers](#php_spammers)|622|622|3|0.4%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|3|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Mon Jun  8 22:46:33 UTC 2015.

The ipset `ri_web_proxies` has **7198** entries, **7198** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11630|11854|7198|60.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|7198|8.7%|100.0%|
[firehol_level3](#firehol_level3)|107701|9625160|3450|0.0%|47.9%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|3402|3.6%|47.2%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1606|5.4%|22.3%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|1104|42.1%|15.3%|
[xroxy](#xroxy)|2136|2136|930|43.5%|12.9%|
[firehol_level2](#firehol_level2)|26368|38001|707|1.8%|9.8%|
[proxyrss](#proxyrss)|1501|1501|571|38.0%|7.9%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|527|7.3%|7.3%|
[proxz](#proxz)|1080|1080|494|45.7%|6.8%|
[blocklist_de](#blocklist_de)|32230|32230|403|1.2%|5.5%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|347|9.9%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|210|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|201|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|140|0.0%|1.9%|
[nixspam](#nixspam)|39998|39998|77|0.1%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|64|0.6%|0.8%|
[php_dictionary](#php_dictionary)|630|630|53|8.4%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|50|0.2%|0.6%|
[php_spammers](#php_spammers)|622|622|45|7.2%|0.6%|
[php_commenters](#php_commenters)|385|385|23|5.9%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|14|2.1%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|8|0.1%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|8|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|4|2.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|4|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6418|6418|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6437|6437|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5089|688943412|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Mon Jun  8 23:30:05 UTC 2015.

The ipset `shunlist` has **1231** entries, **1231** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107701|9625160|1231|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|1224|0.6%|99.4%|
[openbl_60d](#openbl_60d)|7208|7208|545|7.5%|44.2%|
[openbl_30d](#openbl_30d)|2882|2882|518|17.9%|42.0%|
[firehol_level2](#firehol_level2)|26368|38001|441|1.1%|35.8%|
[blocklist_de](#blocklist_de)|32230|32230|436|1.3%|35.4%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|425|24.7%|34.5%|
[et_compromised](#et_compromised)|1678|1678|407|24.2%|33.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|402|12.2%|32.6%|
[openbl_7d](#openbl_7d)|824|824|214|25.9%|17.3%|
[firehol_level1](#firehol_level1)|5089|688943412|178|0.0%|14.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|114|0.0%|9.2%|
[et_block](#et_block)|999|18343755|102|0.0%|8.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|94|0.0%|7.6%|
[dshield](#dshield)|20|5120|90|1.7%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|68|0.0%|5.5%|
[sslbl](#sslbl)|380|380|64|16.8%|5.1%|
[openbl_1d](#openbl_1d)|135|135|61|45.1%|4.9%|
[ciarmy](#ciarmy)|445|445|37|8.3%|3.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|31|0.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|25|0.0%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|22|13.4%|1.7%|
[voipbl](#voipbl)|10507|10919|11|0.1%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|4|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|3|0.0%|0.2%|
[nixspam](#nixspam)|39998|39998|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6418|6418|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6437|6437|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Mon Jun  8 16:00:00 UTC 2015.

The ipset `snort_ipfilter` has **9624** entries, **9624** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107701|9625160|9624|0.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|1157|1.4%|12.0%|
[et_tor](#et_tor)|6400|6400|1083|16.9%|11.2%|
[dm_tor](#dm_tor)|6418|6418|1048|16.3%|10.8%|
[bm_tor](#bm_tor)|6437|6437|1048|16.2%|10.8%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|798|0.8%|8.2%|
[firehol_level2](#firehol_level2)|26368|38001|656|1.7%|6.8%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|636|2.1%|6.6%|
[nixspam](#nixspam)|39998|39998|480|1.2%|4.9%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|397|5.5%|4.1%|
[et_block](#et_block)|999|18343755|301|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5089|688943412|298|0.0%|3.0%|
[blocklist_de](#blocklist_de)|32230|32230|296|0.9%|3.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|260|2.1%|2.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|254|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|251|1.2%|2.6%|
[zeus](#zeus)|232|232|201|86.6%|2.0%|
[zeus_badips](#zeus_badips)|203|203|179|88.1%|1.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|172|46.2%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|163|0.0%|1.6%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|123|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|107|0.0%|1.1%|
[php_dictionary](#php_dictionary)|630|630|85|13.4%|0.8%|
[php_spammers](#php_spammers)|622|622|82|13.1%|0.8%|
[feodo](#feodo)|102|102|79|77.4%|0.8%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|64|0.8%|0.6%|
[php_commenters](#php_commenters)|385|385|51|13.2%|0.5%|
[xroxy](#xroxy)|2136|2136|38|1.7%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|33|0.9%|0.3%|
[sslbl](#sslbl)|380|380|31|8.1%|0.3%|
[openbl_60d](#openbl_60d)|7208|7208|28|0.3%|0.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|28|2.1%|0.2%|
[proxz](#proxz)|1080|1080|24|2.2%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|20|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|15|0.0%|0.1%|
[php_harvesters](#php_harvesters)|366|366|14|3.8%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|14|0.5%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|13|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|9|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|6|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2882|2882|6|0.2%|0.0%|
[proxyrss](#proxyrss)|1501|1501|4|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|4|3.2%|0.0%|
[shunlist](#shunlist)|1231|1231|3|0.2%|0.0%|
[openbl_7d](#openbl_7d)|824|824|2|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|2|1.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|133|133|1|0.7%|0.0%|

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
[firehol_level1](#firehol_level1)|5089|688943412|18338560|2.6%|100.0%|
[et_block](#et_block)|999|18343755|18338560|99.9%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|107701|9625160|6933026|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3720|670264216|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|1374|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1017|1.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|311|1.0%|0.0%|
[firehol_level2](#firehol_level2)|26368|38001|246|0.6%|0.0%|
[openbl_60d](#openbl_60d)|7208|7208|239|3.3%|0.0%|
[blocklist_de](#blocklist_de)|32230|32230|184|0.5%|0.0%|
[openbl_30d](#openbl_30d)|2882|2882|120|4.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|116|3.5%|0.0%|
[et_compromised](#et_compromised)|1678|1678|101|6.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|101|5.8%|0.0%|
[shunlist](#shunlist)|1231|1231|94|7.6%|0.0%|
[nixspam](#nixspam)|39998|39998|88|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|80|1.1%|0.0%|
[openbl_7d](#openbl_7d)|824|824|42|5.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|41|1.1%|0.0%|
[php_commenters](#php_commenters)|385|385|29|7.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|21|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|20|0.2%|0.0%|
[zeus_badips](#zeus_badips)|203|203|16|7.8%|0.0%|
[zeus](#zeus)|232|232|16|6.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|15|0.6%|0.0%|
[voipbl](#voipbl)|10507|10919|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|135|135|13|9.6%|0.0%|
[php_dictionary](#php_dictionary)|630|630|6|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|5|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|5|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[malc0de](#malc0de)|342|342|4|1.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6418|6418|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6437|6437|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|2|0.0%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|1|1.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5089|688943412|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|999|18343755|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|107701|9625160|90|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|79|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|15|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|10|0.0%|0.0%|
[firehol_level2](#firehol_level2)|26368|38001|8|0.0%|0.0%|
[php_commenters](#php_commenters)|385|385|7|1.8%|0.0%|
[blocklist_de](#blocklist_de)|32230|32230|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|5|2.4%|0.0%|
[zeus](#zeus)|232|232|5|2.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|3|1.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|3|0.0%|0.0%|
[nixspam](#nixspam)|39998|39998|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|2|0.0%|0.0%|
[virbl](#virbl)|13|13|1|7.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7208|7208|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2882|2882|1|0.0%|0.0%|
[malc0de](#malc0de)|342|342|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6418|6418|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|1|0.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Mon Jun  8 23:15:06 UTC 2015.

The ipset `sslbl` has **380** entries, **380** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5089|688943412|380|0.0%|100.0%|
[firehol_level3](#firehol_level3)|107701|9625160|95|0.0%|25.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|68|0.0%|17.8%|
[shunlist](#shunlist)|1231|1231|64|5.1%|16.8%|
[feodo](#feodo)|102|102|37|36.2%|9.7%|
[et_block](#et_block)|999|18343755|37|0.0%|9.7%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|31|0.3%|8.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|30|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|4|0.0%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11630|11854|1|0.0%|0.2%|
[firehol_level2](#firehol_level2)|26368|38001|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|32230|32230|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Mon Jun  8 23:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7133** entries, **7133** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26368|38001|7133|18.7%|100.0%|
[firehol_level3](#firehol_level3)|107701|9625160|4425|0.0%|62.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|4387|4.7%|61.5%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|3882|13.2%|54.4%|
[blocklist_de](#blocklist_de)|32230|32230|1390|4.3%|19.4%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|1328|37.9%|18.6%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|1101|1.3%|15.4%|
[firehol_proxies](#firehol_proxies)|11630|11854|889|7.4%|12.4%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|527|7.3%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|513|0.0%|7.1%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|397|4.1%|5.5%|
[et_tor](#et_tor)|6400|6400|357|5.5%|5.0%|
[dm_tor](#dm_tor)|6418|6418|351|5.4%|4.9%|
[bm_tor](#bm_tor)|6437|6437|351|5.4%|4.9%|
[proxyrss](#proxyrss)|1501|1501|344|22.9%|4.8%|
[xroxy](#xroxy)|2136|2136|288|13.4%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|199|0.0%|2.7%|
[proxz](#proxz)|1080|1080|190|17.5%|2.6%|
[php_commenters](#php_commenters)|385|385|159|41.2%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|156|41.9%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|147|5.6%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|123|0.0%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|102|62.5%|1.4%|
[firehol_level1](#firehol_level1)|5089|688943412|81|0.0%|1.1%|
[et_block](#et_block)|999|18343755|81|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|80|0.0%|1.1%|
[nixspam](#nixspam)|39998|39998|67|0.1%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|60|0.3%|0.8%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|52|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|47|0.2%|0.6%|
[php_spammers](#php_spammers)|622|622|44|7.0%|0.6%|
[php_harvesters](#php_harvesters)|366|366|43|11.7%|0.6%|
[php_dictionary](#php_dictionary)|630|630|32|5.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|27|0.4%|0.3%|
[openbl_60d](#openbl_60d)|7208|7208|20|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|5|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[et_compromised](#et_compromised)|1678|1678|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1231|1231|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2882|2882|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|133|133|1|0.7%|0.0%|

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
[firehol_level3](#firehol_level3)|107701|9625160|92247|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|29202|99.7%|31.6%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|5765|7.0%|6.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5743|0.0%|6.2%|
[firehol_level2](#firehol_level2)|26368|38001|5726|15.0%|6.2%|
[firehol_proxies](#firehol_proxies)|11630|11854|5126|43.2%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|4387|61.5%|4.7%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|3402|47.2%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2489|0.0%|2.6%|
[blocklist_de](#blocklist_de)|32230|32230|2457|7.6%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|2143|61.1%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1511|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|1485|56.7%|1.6%|
[xroxy](#xroxy)|2136|2136|1259|58.9%|1.3%|
[firehol_level1](#firehol_level1)|5089|688943412|1101|0.0%|1.1%|
[et_block](#et_block)|999|18343755|1020|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1017|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|798|8.2%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|732|0.0%|0.7%|
[proxyrss](#proxyrss)|1501|1501|666|44.3%|0.7%|
[et_tor](#et_tor)|6400|6400|645|10.0%|0.6%|
[proxz](#proxz)|1080|1080|640|59.2%|0.6%|
[dm_tor](#dm_tor)|6418|6418|630|9.8%|0.6%|
[bm_tor](#bm_tor)|6437|6437|626|9.7%|0.6%|
[php_commenters](#php_commenters)|385|385|287|74.5%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|238|1.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|232|62.3%|0.2%|
[nixspam](#nixspam)|39998|39998|213|0.5%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|210|1.2%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|197|0.1%|0.2%|
[php_spammers](#php_spammers)|622|622|127|20.4%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|118|72.3%|0.1%|
[php_dictionary](#php_dictionary)|630|630|117|18.5%|0.1%|
[php_harvesters](#php_harvesters)|366|366|80|21.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|79|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|61|1.1%|0.0%|
[openbl_60d](#openbl_60d)|7208|7208|54|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|46|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|37|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|20|3.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|19|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|13|0.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|13|0.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|12|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|133|133|5|3.7%|0.0%|
[shunlist](#shunlist)|1231|1231|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|2882|2882|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[openbl_7d](#openbl_7d)|824|824|3|0.3%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|2|0.9%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|2|0.0%|0.0%|
[ciarmy](#ciarmy)|445|445|1|0.2%|0.0%|
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
[firehol_level3](#firehol_level3)|107701|9625160|29205|0.3%|99.7%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|29202|31.6%|99.7%|
[firehol_level2](#firehol_level2)|26368|38001|4861|12.7%|16.6%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|3882|54.4%|13.2%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|2824|3.4%|9.6%|
[firehol_proxies](#firehol_proxies)|11630|11854|2433|20.5%|8.3%|
[blocklist_de](#blocklist_de)|32230|32230|2055|6.3%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1899|0.0%|6.4%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|1895|54.0%|6.4%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|1606|22.3%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|853|0.0%|2.9%|
[xroxy](#xroxy)|2136|2136|669|31.3%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|636|6.6%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|635|24.2%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|558|0.0%|1.9%|
[et_tor](#et_tor)|6400|6400|518|8.0%|1.7%|
[proxyrss](#proxyrss)|1501|1501|516|34.3%|1.7%|
[dm_tor](#dm_tor)|6418|6418|502|7.8%|1.7%|
[bm_tor](#bm_tor)|6437|6437|499|7.7%|1.7%|
[proxz](#proxz)|1080|1080|461|42.6%|1.5%|
[firehol_level1](#firehol_level1)|5089|688943412|322|0.0%|1.0%|
[et_block](#et_block)|999|18343755|312|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|311|0.0%|1.0%|
[php_commenters](#php_commenters)|385|385|215|55.8%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|190|51.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|158|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|129|0.6%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|124|0.7%|0.4%|
[nixspam](#nixspam)|39998|39998|119|0.2%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|109|66.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|96|0.0%|0.3%|
[php_dictionary](#php_dictionary)|630|630|79|12.5%|0.2%|
[php_spammers](#php_spammers)|622|622|72|11.5%|0.2%|
[php_harvesters](#php_harvesters)|366|366|60|16.3%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|40|0.7%|0.1%|
[openbl_60d](#openbl_60d)|7208|7208|24|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|15|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|10|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|6|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|6|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|6|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|5|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[shunlist](#shunlist)|1231|1231|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2882|2882|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|445|445|1|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|133|133|1|0.7%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Mon Jun  8 23:12:04 UTC 2015.

The ipset `virbl` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107701|9625160|13|0.0%|100.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|
[firehol_level1](#firehol_level1)|5089|688943412|1|0.0%|7.6%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Mon Jun  8 21:09:29 UTC 2015.

The ipset `voipbl` has **10507** entries, **10919** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1600|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|434|0.0%|3.9%|
[firehol_level1](#firehol_level1)|5089|688943412|333|0.0%|3.0%|
[fullbogons](#fullbogons)|3720|670264216|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|299|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|189|0.1%|1.7%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|78|0.0%|0.7%|
[firehol_level3](#firehol_level3)|107701|9625160|59|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|37|0.0%|0.3%|
[firehol_level2](#firehol_level2)|26368|38001|37|0.0%|0.3%|
[blocklist_de](#blocklist_de)|32230|32230|32|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|28|30.4%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|15|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|14|0.0%|0.1%|
[et_block](#et_block)|999|18343755|14|0.0%|0.1%|
[shunlist](#shunlist)|1231|1231|11|0.8%|0.1%|
[openbl_60d](#openbl_60d)|7208|7208|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[ciarmy](#ciarmy)|445|445|4|0.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2882|2882|3|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6418|6418|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6437|6437|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|2|0.1%|0.0%|
[nixspam](#nixspam)|39998|39998|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11630|11854|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3279|3279|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Mon Jun  8 23:33:01 UTC 2015.

The ipset `xroxy` has **2136** entries, **2136** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11630|11854|2136|18.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18108|82117|2136|2.6%|100.0%|
[firehol_level3](#firehol_level3)|107701|9625160|1273|0.0%|59.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1259|1.3%|58.9%|
[ri_web_proxies](#ri_web_proxies)|7198|7198|930|12.9%|43.5%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|669|2.2%|31.3%|
[proxz](#proxz)|1080|1080|397|36.7%|18.5%|
[ri_connect_proxies](#ri_connect_proxies)|2617|2617|381|14.5%|17.8%|
[firehol_level2](#firehol_level2)|26368|38001|368|0.9%|17.2%|
[proxyrss](#proxyrss)|1501|1501|361|24.0%|16.9%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|288|4.0%|13.4%|
[blocklist_de](#blocklist_de)|32230|32230|202|0.6%|9.4%|
[blocklist_de_bots](#blocklist_de_bots)|3503|3503|165|4.7%|7.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|104|0.0%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.7%|
[nixspam](#nixspam)|39998|39998|54|0.1%|2.5%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|39|0.1%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|38|0.3%|1.7%|
[php_dictionary](#php_dictionary)|630|630|38|6.0%|1.7%|
[php_spammers](#php_spammers)|622|622|30|4.8%|1.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[php_commenters](#php_commenters)|385|385|8|2.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|163|163|5|3.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6418|6418|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1716|1716|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6437|6437|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5481|5481|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16804|16804|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  8 18:01:32 UTC 2015.

The ipset `zeus` has **232** entries, **232** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5089|688943412|232|0.0%|100.0%|
[et_block](#et_block)|999|18343755|229|0.0%|98.7%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|87.5%|
[firehol_level3](#firehol_level3)|107701|9625160|203|0.0%|87.5%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|201|2.0%|86.6%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|63|0.0%|27.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|2.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7208|7208|2|0.0%|0.8%|
[firehol_level2](#firehol_level2)|26368|38001|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|1|0.0%|0.4%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.4%|
[openbl_30d](#openbl_30d)|2882|2882|1|0.0%|0.4%|
[nixspam](#nixspam)|39998|39998|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|1|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|32230|32230|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Mon Jun  8 23:15:25 UTC 2015.

The ipset `zeus_badips` has **203** entries, **203** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|232|232|203|87.5%|100.0%|
[firehol_level1](#firehol_level1)|5089|688943412|203|0.0%|100.0%|
[et_block](#et_block)|999|18343755|203|0.0%|100.0%|
[firehol_level3](#firehol_level3)|107701|9625160|181|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|179|1.8%|88.1%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|38|0.0%|18.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2|0.0%|0.9%|
[firehol_level2](#firehol_level2)|26368|38001|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29278|29278|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7133|7133|1|0.0%|0.4%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7208|7208|1|0.0%|0.4%|
[nixspam](#nixspam)|39998|39998|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|19540|19540|1|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2434|2434|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|32230|32230|1|0.0%|0.4%|
