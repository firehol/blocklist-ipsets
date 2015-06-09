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

The following list was automatically generated on Tue Jun  9 21:46:17 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|184826 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|32050 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|16288 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3256 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|4930 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|702 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2797 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|19708 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|76 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|3111 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|177 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6569 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1721 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|451 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|172 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6558 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|999 subnets, 18343755 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|509 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1678 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6400 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|103 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)|ipv4 hash:net|18450 subnets, 82472 unique IPs|updated every 1 min  from [this link]()
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5150 subnets, 688981125 unique IPs|updated every 1 min  from [this link]()
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|26283 subnets, 37939 unique IPs|updated every 1 min  from [this link]()
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)|ipv4 hash:net|108574 subnets, 9626093 unique IPs|updated every 1 min  from [this link]()
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|11826 subnets, 12064 unique IPs|updated every 1 min  from [this link]()
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|29885 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|144 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2853 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7050 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|766 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|403 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|666 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|378 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|661 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1544 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1158 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2661 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7349 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1302 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|10136 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|653 subnets, 18340608 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|380 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7240 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92512 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29277 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|20 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10522 subnets, 10934 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2145 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|232 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|202 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Tue Jun  9 16:00:31 UTC 2015.

The ipset `alienvault_reputation` has **184826** entries, **184826** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14134|0.0%|7.6%|
[openbl_60d](#openbl_60d)|7050|7050|7023|99.6%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6261|0.0%|3.3%|
[et_block](#et_block)|999|18343755|5280|0.0%|2.8%|
[firehol_level3](#firehol_level3)|108574|9626093|5188|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4218|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5150|688981125|3574|0.0%|1.9%|
[openbl_30d](#openbl_30d)|2853|2853|2832|99.2%|1.5%|
[dshield](#dshield)|20|5120|2313|45.1%|1.2%|
[firehol_level2](#firehol_level2)|26283|37939|1470|3.8%|0.7%|
[blocklist_de](#blocklist_de)|32050|32050|1416|4.4%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1374|0.0%|0.7%|
[shunlist](#shunlist)|1302|1302|1273|97.7%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|1173|37.7%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|1106|64.2%|0.5%|
[et_compromised](#et_compromised)|1678|1678|1080|64.3%|0.5%|
[openbl_7d](#openbl_7d)|766|766|756|98.6%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|451|451|441|97.7%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|288|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|202|0.2%|0.1%|
[voipbl](#voipbl)|10522|10934|191|1.7%|0.1%|
[openbl_1d](#openbl_1d)|144|144|134|93.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|132|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|118|1.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|99|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|71|0.3%|0.0%|
[sslbl](#sslbl)|380|380|68|17.8%|0.0%|
[zeus](#zeus)|232|232|62|26.7%|0.0%|
[nixspam](#nixspam)|29885|29885|59|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|56|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|49|0.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|47|1.6%|0.0%|
[et_tor](#et_tor)|6400|6400|41|0.6%|0.0%|
[dm_tor](#dm_tor)|6558|6558|41|0.6%|0.0%|
[bm_tor](#bm_tor)|6569|6569|41|0.6%|0.0%|
[zeus_badips](#zeus_badips)|202|202|37|18.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|36|20.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11826|12064|34|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|22|0.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|21|0.4%|0.0%|
[php_commenters](#php_commenters)|403|403|18|4.4%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|76|76|17|22.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|11|2.9%|0.0%|
[malc0de](#malc0de)|338|338|11|3.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|10|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|9|1.2%|0.0%|
[php_dictionary](#php_dictionary)|666|666|8|1.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|7|0.5%|0.0%|
[xroxy](#xroxy)|2145|2145|5|0.2%|0.0%|
[php_spammers](#php_spammers)|661|661|5|0.7%|0.0%|
[et_botcc](#et_botcc)|509|509|5|0.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|4|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|4|2.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|3|0.1%|0.0%|
[proxz](#proxz)|1158|1158|3|0.2%|0.0%|
[feodo](#feodo)|103|103|2|1.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Tue Jun  9 21:42:03 UTC 2015.

The ipset `blocklist_de` has **32050** entries, **32050** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26283|37939|32050|84.4%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|19697|99.9%|61.4%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|16256|99.8%|50.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|4899|99.3%|15.2%|
[firehol_level3](#firehol_level3)|108574|9626093|3938|0.0%|12.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3927|0.0%|12.2%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|3245|99.6%|10.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|3101|99.6%|9.6%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|2797|100.0%|8.7%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2563|2.7%|7.9%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2144|7.3%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1621|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1559|0.0%|4.8%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|1416|0.7%|4.4%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|1376|19.0%|4.2%|
[openbl_60d](#openbl_60d)|7050|7050|1047|14.8%|3.2%|
[openbl_30d](#openbl_30d)|2853|2853|847|29.6%|2.6%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|739|42.9%|2.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|702|100.0%|2.1%|
[nixspam](#nixspam)|29885|29885|657|2.1%|2.0%|
[et_compromised](#et_compromised)|1678|1678|643|38.3%|2.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|606|0.7%|1.8%|
[firehol_proxies](#firehol_proxies)|11826|12064|592|4.9%|1.8%|
[shunlist](#shunlist)|1302|1302|464|35.6%|1.4%|
[openbl_7d](#openbl_7d)|766|766|415|54.1%|1.2%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|412|5.6%|1.2%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|233|2.2%|0.7%|
[firehol_level1](#firehol_level1)|5150|688981125|229|0.0%|0.7%|
[et_block](#et_block)|999|18343755|220|0.0%|0.6%|
[xroxy](#xroxy)|2145|2145|206|9.6%|0.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|206|0.0%|0.6%|
[proxyrss](#proxyrss)|1544|1544|204|13.2%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|177|100.0%|0.5%|
[proxz](#proxz)|1158|1158|172|14.8%|0.5%|
[openbl_1d](#openbl_1d)|144|144|119|82.6%|0.3%|
[php_dictionary](#php_dictionary)|666|666|101|15.1%|0.3%|
[php_commenters](#php_commenters)|403|403|98|24.3%|0.3%|
[php_spammers](#php_spammers)|661|661|94|14.2%|0.2%|
[dshield](#dshield)|20|5120|86|1.6%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|70|2.6%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|60|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|76|76|57|75.0%|0.1%|
[ciarmy](#ciarmy)|451|451|39|8.6%|0.1%|
[php_harvesters](#php_harvesters)|378|378|37|9.7%|0.1%|
[voipbl](#voipbl)|10522|10934|28|0.2%|0.0%|
[dm_tor](#dm_tor)|6558|6558|13|0.1%|0.0%|
[bm_tor](#bm_tor)|6569|6569|13|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|11|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|8|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Tue Jun  9 21:28:05 UTC 2015.

The ipset `blocklist_de_apache` has **16288** entries, **16288** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26283|37939|16256|42.8%|99.8%|
[blocklist_de](#blocklist_de)|32050|32050|16256|50.7%|99.8%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|11059|56.1%|67.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|4930|100.0%|30.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2432|0.0%|14.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1337|0.0%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1107|0.0%|6.7%|
[firehol_level3](#firehol_level3)|108574|9626093|299|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|217|0.2%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|134|0.4%|0.8%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|132|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|63|0.8%|0.3%|
[nixspam](#nixspam)|29885|29885|43|0.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|35|19.7%|0.2%|
[ciarmy](#ciarmy)|451|451|33|7.3%|0.2%|
[php_commenters](#php_commenters)|403|403|32|7.9%|0.1%|
[shunlist](#shunlist)|1302|1302|31|2.3%|0.1%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|25|0.2%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|22|0.6%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|18|0.0%|0.1%|
[dm_tor](#dm_tor)|6558|6558|11|0.1%|0.0%|
[bm_tor](#bm_tor)|6569|6569|11|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|10|0.1%|0.0%|
[firehol_level1](#firehol_level1)|5150|688981125|9|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11826|12064|8|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|7|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|7|1.0%|0.0%|
[et_block](#et_block)|999|18343755|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|5|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7050|7050|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|4|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|766|766|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|144|144|1|0.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Tue Jun  9 21:28:07 UTC 2015.

The ipset `blocklist_de_bots` has **3256** entries, **3256** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26283|37939|3245|8.5%|99.6%|
[blocklist_de](#blocklist_de)|32050|32050|3245|10.1%|99.6%|
[firehol_level3](#firehol_level3)|108574|9626093|2249|0.0%|69.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2211|2.3%|67.9%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1955|6.6%|60.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|1295|17.8%|39.7%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|496|0.6%|15.2%|
[firehol_proxies](#firehol_proxies)|11826|12064|494|4.0%|15.1%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|349|4.7%|10.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|210|0.0%|6.4%|
[proxyrss](#proxyrss)|1544|1544|203|13.1%|6.2%|
[xroxy](#xroxy)|2145|2145|156|7.2%|4.7%|
[proxz](#proxz)|1158|1158|147|12.6%|4.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|129|72.8%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|111|0.0%|3.4%|
[php_commenters](#php_commenters)|403|403|77|19.1%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|67|2.5%|2.0%|
[firehol_level1](#firehol_level1)|5150|688981125|61|0.0%|1.8%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|57|0.0%|1.7%|
[et_block](#et_block)|999|18343755|57|0.0%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|50|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|35|0.0%|1.0%|
[nixspam](#nixspam)|29885|29885|30|0.1%|0.9%|
[php_harvesters](#php_harvesters)|378|378|29|7.6%|0.8%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|24|0.2%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|22|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|22|0.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|22|0.0%|0.6%|
[php_spammers](#php_spammers)|661|661|19|2.8%|0.5%|
[php_dictionary](#php_dictionary)|666|666|17|2.5%|0.5%|
[openbl_60d](#openbl_60d)|7050|7050|6|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6569|6569|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Tue Jun  9 21:28:09 UTC 2015.

The ipset `blocklist_de_bruteforce` has **4930** entries, **4930** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|4930|30.2%|100.0%|
[firehol_level2](#firehol_level2)|26283|37939|4899|12.9%|99.3%|
[blocklist_de](#blocklist_de)|32050|32050|4899|15.2%|99.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|337|0.0%|6.8%|
[firehol_level3](#firehol_level3)|108574|9626093|92|0.0%|1.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|72|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|68|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|49|0.1%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|45|0.0%|0.9%|
[nixspam](#nixspam)|29885|29885|42|0.1%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|32|0.4%|0.6%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|21|0.2%|0.4%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|21|0.0%|0.4%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|15|0.0%|0.3%|
[php_commenters](#php_commenters)|403|403|11|2.7%|0.2%|
[dm_tor](#dm_tor)|6558|6558|8|0.1%|0.1%|
[bm_tor](#bm_tor)|6569|6569|8|0.1%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|8|4.5%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|7|0.0%|0.1%|
[php_spammers](#php_spammers)|661|661|7|1.0%|0.1%|
[firehol_proxies](#firehol_proxies)|11826|12064|7|0.0%|0.1%|
[et_tor](#et_tor)|6400|6400|6|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.1%|
[php_dictionary](#php_dictionary)|666|666|5|0.7%|0.1%|
[firehol_level1](#firehol_level1)|5150|688981125|5|0.0%|0.1%|
[et_block](#et_block)|999|18343755|5|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.0%|
[shunlist](#shunlist)|1302|1302|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Tue Jun  9 21:28:06 UTC 2015.

The ipset `blocklist_de_ftp` has **702** entries, **702** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26283|37939|702|1.8%|100.0%|
[blocklist_de](#blocklist_de)|32050|32050|702|2.1%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|97|0.0%|13.8%|
[firehol_level3](#firehol_level3)|108574|9626093|17|0.0%|2.4%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|12|0.0%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|12|0.0%|1.7%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|9|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|5|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|4|0.0%|0.5%|
[nixspam](#nixspam)|29885|29885|4|0.0%|0.5%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.2%|
[openbl_60d](#openbl_60d)|7050|7050|2|0.0%|0.2%|
[openbl_30d](#openbl_30d)|2853|2853|2|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.2%|
[shunlist](#shunlist)|1302|1302|1|0.0%|0.1%|
[openbl_7d](#openbl_7d)|766|766|1|0.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5150|688981125|1|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|
[ciarmy](#ciarmy)|451|451|1|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|1|0.0%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Tue Jun  9 21:42:08 UTC 2015.

The ipset `blocklist_de_imap` has **2797** entries, **2797** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26283|37939|2797|7.3%|100.0%|
[blocklist_de](#blocklist_de)|32050|32050|2797|8.7%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|2796|14.1%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|316|0.0%|11.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|55|0.0%|1.9%|
[firehol_level3](#firehol_level3)|108574|9626093|47|0.0%|1.6%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|47|0.0%|1.6%|
[openbl_60d](#openbl_60d)|7050|7050|33|0.4%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|30|0.0%|1.0%|
[nixspam](#nixspam)|29885|29885|29|0.0%|1.0%|
[openbl_30d](#openbl_30d)|2853|2853|28|0.9%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|13|0.0%|0.4%|
[firehol_level1](#firehol_level1)|5150|688981125|13|0.0%|0.4%|
[et_block](#et_block)|999|18343755|13|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|9|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|9|0.0%|0.3%|
[openbl_7d](#openbl_7d)|766|766|9|1.1%|0.3%|
[et_compromised](#et_compromised)|1678|1678|4|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|4|0.2%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|3|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.1%|
[shunlist](#shunlist)|1302|1302|2|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|2|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11826|12064|2|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|2|0.0%|0.0%|
[xroxy](#xroxy)|2145|2145|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|1|0.0%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|144|144|1|0.6%|0.0%|
[ciarmy](#ciarmy)|451|451|1|0.2%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Tue Jun  9 21:28:05 UTC 2015.

The ipset `blocklist_de_mail` has **19708** entries, **19708** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26283|37939|19697|51.9%|99.9%|
[blocklist_de](#blocklist_de)|32050|32050|19697|61.4%|99.9%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|11059|67.8%|56.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2821|0.0%|14.3%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|2796|99.9%|14.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1403|0.0%|7.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1274|0.0%|6.4%|
[nixspam](#nixspam)|29885|29885|566|1.8%|2.8%|
[firehol_level3](#firehol_level3)|108574|9626093|443|0.0%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|253|0.2%|1.2%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|187|1.8%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|138|0.4%|0.7%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|93|0.1%|0.4%|
[firehol_proxies](#firehol_proxies)|11826|12064|91|0.7%|0.4%|
[php_dictionary](#php_dictionary)|666|666|79|11.8%|0.4%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|71|0.0%|0.3%|
[php_spammers](#php_spammers)|661|661|67|10.1%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|56|0.7%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|55|0.7%|0.2%|
[xroxy](#xroxy)|2145|2145|50|2.3%|0.2%|
[openbl_60d](#openbl_60d)|7050|7050|42|0.5%|0.2%|
[openbl_30d](#openbl_30d)|2853|2853|35|1.2%|0.1%|
[proxz](#proxz)|1158|1158|25|2.1%|0.1%|
[php_commenters](#php_commenters)|403|403|25|6.2%|0.1%|
[firehol_level1](#firehol_level1)|5150|688981125|25|0.0%|0.1%|
[et_block](#et_block)|999|18343755|24|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|23|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|23|12.9%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|22|0.6%|0.1%|
[openbl_7d](#openbl_7d)|766|766|9|1.1%|0.0%|
[et_compromised](#et_compromised)|1678|1678|7|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|6|0.3%|0.0%|
[php_harvesters](#php_harvesters)|378|378|5|1.3%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[shunlist](#shunlist)|1302|1302|3|0.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6569|6569|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1544|1544|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|144|144|1|0.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ciarmy](#ciarmy)|451|451|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Tue Jun  9 21:28:06 UTC 2015.

The ipset `blocklist_de_sip` has **76** entries, **76** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26283|37939|57|0.1%|75.0%|
[blocklist_de](#blocklist_de)|32050|32050|57|0.1%|75.0%|
[voipbl](#voipbl)|10522|10934|23|0.2%|30.2%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|17|0.0%|22.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13|0.0%|17.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|7.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|7.8%|
[firehol_level3](#firehol_level3)|108574|9626093|3|0.0%|3.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|2.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.6%|
[firehol_level1](#firehol_level1)|5150|688981125|2|0.0%|2.6%|
[et_block](#et_block)|999|18343755|2|0.0%|2.6%|
[shunlist](#shunlist)|1302|1302|1|0.0%|1.3%|
[et_botcc](#et_botcc)|509|509|1|0.1%|1.3%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Tue Jun  9 21:28:03 UTC 2015.

The ipset `blocklist_de_ssh` has **3111** entries, **3111** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26283|37939|3101|8.1%|99.6%|
[blocklist_de](#blocklist_de)|32050|32050|3101|9.6%|99.6%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|1173|0.6%|37.7%|
[firehol_level3](#firehol_level3)|108574|9626093|1080|0.0%|34.7%|
[openbl_60d](#openbl_60d)|7050|7050|990|14.0%|31.8%|
[openbl_30d](#openbl_30d)|2853|2853|805|28.2%|25.8%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|731|42.4%|23.4%|
[et_compromised](#et_compromised)|1678|1678|635|37.8%|20.4%|
[shunlist](#shunlist)|1302|1302|428|32.8%|13.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|412|0.0%|13.2%|
[openbl_7d](#openbl_7d)|766|766|405|52.8%|13.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|137|0.0%|4.4%|
[firehol_level1](#firehol_level1)|5150|688981125|130|0.0%|4.1%|
[et_block](#et_block)|999|18343755|129|0.0%|4.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|118|0.0%|3.7%|
[openbl_1d](#openbl_1d)|144|144|117|81.2%|3.7%|
[dshield](#dshield)|20|5120|81|1.5%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|54|0.0%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|30|16.9%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|20|0.0%|0.6%|
[nixspam](#nixspam)|29885|29885|11|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|5|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.1%|
[ciarmy](#ciarmy)|451|451|3|0.6%|0.0%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6569|6569|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Tue Jun  9 21:42:11 UTC 2015.

The ipset `blocklist_de_strongips` has **177** entries, **177** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26283|37939|177|0.4%|100.0%|
[blocklist_de](#blocklist_de)|32050|32050|177|0.5%|100.0%|
[firehol_level3](#firehol_level3)|108574|9626093|156|0.0%|88.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|129|0.1%|72.8%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|129|3.9%|72.8%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|116|0.3%|65.5%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|108|1.4%|61.0%|
[php_commenters](#php_commenters)|403|403|45|11.1%|25.4%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|36|0.0%|20.3%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|35|0.2%|19.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|30|0.9%|16.9%|
[openbl_60d](#openbl_60d)|7050|7050|25|0.3%|14.1%|
[openbl_30d](#openbl_30d)|2853|2853|24|0.8%|13.5%|
[openbl_7d](#openbl_7d)|766|766|23|3.0%|12.9%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|23|0.1%|12.9%|
[shunlist](#shunlist)|1302|1302|21|1.6%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|17|0.0%|9.6%|
[openbl_1d](#openbl_1d)|144|144|16|11.1%|9.0%|
[firehol_level1](#firehol_level1)|5150|688981125|10|0.0%|5.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|8|0.1%|4.5%|
[php_spammers](#php_spammers)|661|661|7|1.0%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|3.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|3.3%|
[et_block](#et_block)|999|18343755|6|0.0%|3.3%|
[xroxy](#xroxy)|2145|2145|5|0.2%|2.8%|
[firehol_proxies](#firehol_proxies)|11826|12064|5|0.0%|2.8%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|5|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|2.2%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|4|0.0%|2.2%|
[proxz](#proxz)|1158|1158|4|0.3%|2.2%|
[proxyrss](#proxyrss)|1544|1544|4|0.2%|2.2%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|2.2%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|3|0.0%|1.6%|
[nixspam](#nixspam)|29885|29885|3|0.0%|1.6%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|1.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|2|0.2%|1.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Tue Jun  9 21:36:04 UTC 2015.

The ipset `bm_tor` has **6569** entries, **6569** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18450|82472|6569|7.9%|100.0%|
[dm_tor](#dm_tor)|6558|6558|6453|98.3%|98.2%|
[et_tor](#et_tor)|6400|6400|5636|88.0%|85.7%|
[firehol_level3](#firehol_level3)|108574|9626093|1099|0.0%|16.7%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1060|10.4%|16.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|633|0.6%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|619|0.0%|9.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|518|1.7%|7.8%|
[firehol_level2](#firehol_level2)|26283|37939|348|0.9%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|344|4.7%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|182|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|165|0.0%|2.5%|
[firehol_proxies](#firehol_proxies)|11826|12064|165|1.3%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|163|43.8%|2.4%|
[php_commenters](#php_commenters)|403|403|48|11.9%|0.7%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|41|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7050|7050|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|32050|32050|13|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|11|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|8|0.1%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.1%|
[nixspam](#nixspam)|29885|29885|5|0.0%|0.0%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[firehol_level1](#firehol_level1)|5150|688981125|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|2|0.0%|0.0%|
[xroxy](#xroxy)|2145|2145|1|0.0%|0.0%|
[shunlist](#shunlist)|1302|1302|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5150|688981125|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10522|10934|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|108574|9626093|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[nixspam](#nixspam)|29885|29885|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|1|0.5%|0.0%|
[ciarmy](#ciarmy)|451|451|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Tue Jun  9 21:27:04 UTC 2015.

The ipset `bruteforceblocker` has **1721** entries, **1721** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108574|9626093|1721|0.0%|100.0%|
[et_compromised](#et_compromised)|1678|1678|1599|95.2%|92.9%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|1106|0.5%|64.2%|
[openbl_60d](#openbl_60d)|7050|7050|1002|14.2%|58.2%|
[openbl_30d](#openbl_30d)|2853|2853|942|33.0%|54.7%|
[firehol_level2](#firehol_level2)|26283|37939|740|1.9%|42.9%|
[blocklist_de](#blocklist_de)|32050|32050|739|2.3%|42.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|731|23.4%|42.4%|
[shunlist](#shunlist)|1302|1302|444|34.1%|25.7%|
[openbl_7d](#openbl_7d)|766|766|328|42.8%|19.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|153|0.0%|8.8%|
[firehol_level1](#firehol_level1)|5150|688981125|109|0.0%|6.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|101|0.0%|5.8%|
[et_block](#et_block)|999|18343755|101|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|84|0.0%|4.8%|
[dshield](#dshield)|20|5120|66|1.2%|3.8%|
[openbl_1d](#openbl_1d)|144|144|61|42.3%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|13|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|6|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|4|0.1%|0.2%|
[firehol_proxies](#firehol_proxies)|11826|12064|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|3|0.0%|0.1%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.1%|
[proxz](#proxz)|1158|1158|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2145|2145|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[nixspam](#nixspam)|29885|29885|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.0%|
[ciarmy](#ciarmy)|451|451|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Tue Jun  9 19:15:18 UTC 2015.

The ipset `ciarmy` has **451** entries, **451** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108574|9626093|451|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|441|0.2%|97.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|98|0.0%|21.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|47|0.0%|10.4%|
[firehol_level2](#firehol_level2)|26283|37939|39|0.1%|8.6%|
[blocklist_de](#blocklist_de)|32050|32050|39|0.1%|8.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|38|0.0%|8.4%|
[shunlist](#shunlist)|1302|1302|33|2.5%|7.3%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|33|0.2%|7.3%|
[firehol_level1](#firehol_level1)|5150|688981125|3|0.0%|0.6%|
[et_block](#et_block)|999|18343755|3|0.0%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|3|0.0%|0.6%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2|0.0%|0.4%|
[openbl_7d](#openbl_7d)|766|766|2|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7050|7050|2|0.0%|0.4%|
[openbl_30d](#openbl_30d)|2853|2853|2|0.0%|0.4%|
[openbl_1d](#openbl_1d)|144|144|2|1.3%|0.4%|
[dshield](#dshield)|20|5120|2|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|1|0.1%|0.2%|

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
[firehol_level3](#firehol_level3)|108574|9626093|172|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|22|0.0%|12.7%|
[malc0de](#malc0de)|338|338|20|5.9%|11.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|2.3%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|4|0.0%|2.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|1.7%|
[firehol_level1](#firehol_level1)|5150|688981125|2|0.0%|1.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1|0.0%|0.5%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.5%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.5%|
[bogons](#bogons)|13|592708608|1|0.0%|0.5%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Tue Jun  9 21:18:05 UTC 2015.

The ipset `dm_tor` has **6558** entries, **6558** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18450|82472|6558|7.9%|100.0%|
[bm_tor](#bm_tor)|6569|6569|6453|98.2%|98.3%|
[et_tor](#et_tor)|6400|6400|5622|87.8%|85.7%|
[firehol_level3](#firehol_level3)|108574|9626093|1096|0.0%|16.7%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1056|10.4%|16.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|635|0.6%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|616|0.0%|9.3%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|519|1.7%|7.9%|
[firehol_level2](#firehol_level2)|26283|37939|350|0.9%|5.3%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|346|4.7%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|182|0.0%|2.7%|
[firehol_proxies](#firehol_proxies)|11826|12064|167|1.3%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|166|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|163|43.8%|2.4%|
[php_commenters](#php_commenters)|403|403|48|11.9%|0.7%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|41|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7050|7050|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|32050|32050|13|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|11|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|8|0.1%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.1%|
[nixspam](#nixspam)|29885|29885|6|0.0%|0.0%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|4|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[firehol_level1](#firehol_level1)|5150|688981125|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|3|0.0%|0.0%|
[xroxy](#xroxy)|2145|2145|1|0.0%|0.0%|
[shunlist](#shunlist)|1302|1302|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Tue Jun  9 19:56:47 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5150|688981125|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|2313|1.2%|45.1%|
[et_block](#et_block)|999|18343755|1280|0.0%|25.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|256|0.0%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|256|0.0%|5.0%|
[firehol_level3](#firehol_level3)|108574|9626093|122|0.0%|2.3%|
[openbl_60d](#openbl_60d)|7050|7050|121|1.7%|2.3%|
[openbl_30d](#openbl_30d)|2853|2853|104|3.6%|2.0%|
[shunlist](#shunlist)|1302|1302|98|7.5%|1.9%|
[firehol_level2](#firehol_level2)|26283|37939|86|0.2%|1.6%|
[blocklist_de](#blocklist_de)|32050|32050|86|0.2%|1.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|81|2.6%|1.5%|
[et_compromised](#et_compromised)|1678|1678|67|3.9%|1.3%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|66|3.8%|1.2%|
[openbl_7d](#openbl_7d)|766|766|18|2.3%|0.3%|
[openbl_1d](#openbl_1d)|144|144|10|6.9%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|3|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2|0.0%|0.0%|
[malc0de](#malc0de)|338|338|2|0.5%|0.0%|
[ciarmy](#ciarmy)|451|451|2|0.4%|0.0%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5150|688981125|18339907|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8533288|2.4%|46.5%|
[firehol_level3](#firehol_level3)|108574|9626093|6933331|72.0%|37.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272541|0.2%|12.3%|
[fullbogons](#fullbogons)|3778|670299624|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130394|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|5280|2.8%|0.0%|
[dshield](#dshield)|20|5120|1280|25.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1041|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1011|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|308|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|299|2.9%|0.0%|
[firehol_level2](#firehol_level2)|26283|37939|290|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7050|7050|248|3.5%|0.0%|
[zeus](#zeus)|232|232|228|98.2%|0.0%|
[blocklist_de](#blocklist_de)|32050|32050|220|0.6%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|129|4.1%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|128|4.4%|0.0%|
[nixspam](#nixspam)|29885|29885|123|0.4%|0.0%|
[shunlist](#shunlist)|1302|1302|105|8.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|101|6.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|101|5.8%|0.0%|
[feodo](#feodo)|103|103|99|96.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|87|1.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|57|1.7%|0.0%|
[openbl_7d](#openbl_7d)|766|766|56|7.3%|0.0%|
[sslbl](#sslbl)|380|380|37|9.7%|0.0%|
[php_commenters](#php_commenters)|403|403|30|7.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[openbl_1d](#openbl_1d)|144|144|26|18.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|24|0.1%|0.0%|
[voipbl](#voipbl)|10522|10934|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|13|0.4%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|9|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|8|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|6|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|6|3.3%|0.0%|
[malc0de](#malc0de)|338|338|5|1.4%|0.0%|
[et_tor](#et_tor)|6400|6400|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6569|6569|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|5|0.1%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[firehol_proxies](#firehol_proxies)|11826|12064|3|0.0%|0.0%|
[ciarmy](#ciarmy)|451|451|3|0.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|76|76|2|2.6%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|184826|184826|5|0.0%|0.9%|
[firehol_level3](#firehol_level3)|108574|9626093|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5150|688981125|1|0.0%|0.1%|
[et_block](#et_block)|999|18343755|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|76|76|1|1.3%|0.1%|

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
[firehol_level3](#firehol_level3)|108574|9626093|1625|0.0%|96.8%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|1599|92.9%|95.2%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|1080|0.5%|64.3%|
[openbl_60d](#openbl_60d)|7050|7050|982|13.9%|58.5%|
[openbl_30d](#openbl_30d)|2853|2853|916|32.1%|54.5%|
[firehol_level2](#firehol_level2)|26283|37939|644|1.6%|38.3%|
[blocklist_de](#blocklist_de)|32050|32050|643|2.0%|38.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|635|20.4%|37.8%|
[shunlist](#shunlist)|1302|1302|419|32.1%|24.9%|
[openbl_7d](#openbl_7d)|766|766|309|40.3%|18.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|151|0.0%|8.9%|
[firehol_level1](#firehol_level1)|5150|688981125|109|0.0%|6.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|101|0.0%|6.0%|
[et_block](#et_block)|999|18343755|101|0.0%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|86|0.0%|5.1%|
[dshield](#dshield)|20|5120|67|1.3%|3.9%|
[openbl_1d](#openbl_1d)|144|144|55|38.1%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|46|0.0%|2.7%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|13|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|7|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|4|0.1%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|11826|12064|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|3|0.0%|0.1%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.1%|
[proxz](#proxz)|1158|1158|2|0.1%|0.1%|
[nixspam](#nixspam)|29885|29885|2|0.0%|0.1%|
[xroxy](#xroxy)|2145|2145|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[ciarmy](#ciarmy)|451|451|1|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|1|0.0%|0.0%|

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
[firehol_anonymous](#firehol_anonymous)|18450|82472|5658|6.8%|88.4%|
[bm_tor](#bm_tor)|6569|6569|5636|85.7%|88.0%|
[dm_tor](#dm_tor)|6558|6558|5622|85.7%|87.8%|
[firehol_level3](#firehol_level3)|108574|9626093|1123|0.0%|17.5%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1084|10.6%|16.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|659|0.7%|10.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|623|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|544|1.8%|8.5%|
[firehol_level2](#firehol_level2)|26283|37939|352|0.9%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|348|4.8%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|186|0.0%|2.9%|
[firehol_proxies](#firehol_proxies)|11826|12064|168|1.3%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|166|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|165|44.3%|2.5%|
[php_commenters](#php_commenters)|403|403|48|11.9%|0.7%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|41|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7050|7050|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|32050|32050|11|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|10|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|7|1.8%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|6|0.1%|0.0%|
[nixspam](#nixspam)|29885|29885|5|0.0%|0.0%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|4|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[firehol_level1](#firehol_level1)|5150|688981125|3|0.0%|0.0%|
[xroxy](#xroxy)|2145|2145|1|0.0%|0.0%|
[shunlist](#shunlist)|1302|1302|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  9 21:36:24 UTC 2015.

The ipset `feodo` has **103** entries, **103** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5150|688981125|103|0.0%|100.0%|
[et_block](#et_block)|999|18343755|99|0.0%|96.1%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|81|0.7%|78.6%|
[firehol_level3](#firehol_level3)|108574|9626093|81|0.0%|78.6%|
[sslbl](#sslbl)|380|380|37|9.7%|35.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|10.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|2|0.0%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.9%|

## firehol_anonymous

**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **18450** entries, **82472** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11826|12064|12064|100.0%|14.6%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|7349|100.0%|8.9%|
[bm_tor](#bm_tor)|6569|6569|6569|100.0%|7.9%|
[dm_tor](#dm_tor)|6558|6558|6558|100.0%|7.9%|
[firehol_level3](#firehol_level3)|108574|9626093|6389|0.0%|7.7%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|5859|6.3%|7.1%|
[et_tor](#et_tor)|6400|6400|5658|88.4%|6.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3422|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2880|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2842|0.0%|3.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2802|9.5%|3.3%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|2661|100.0%|3.2%|
[xroxy](#xroxy)|2145|2145|2145|100.0%|2.6%|
[proxyrss](#proxyrss)|1544|1544|1544|100.0%|1.8%|
[firehol_level2](#firehol_level2)|26283|37939|1314|3.4%|1.5%|
[proxz](#proxz)|1158|1158|1158|100.0%|1.4%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1154|11.3%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|1005|13.8%|1.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.8%|
[blocklist_de](#blocklist_de)|32050|32050|606|1.8%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|496|15.2%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|0.4%|
[nixspam](#nixspam)|29885|29885|159|0.5%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|93|0.4%|0.1%|
[php_dictionary](#php_dictionary)|666|666|87|13.0%|0.1%|
[voipbl](#voipbl)|10522|10934|78|0.7%|0.0%|
[php_commenters](#php_commenters)|403|403|76|18.8%|0.0%|
[php_spammers](#php_spammers)|661|661|73|11.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|56|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|28|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7050|7050|23|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|18|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|16|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|15|0.3%|0.0%|
[php_harvesters](#php_harvesters)|378|378|12|3.1%|0.0%|
[et_block](#et_block)|999|18343755|8|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5150|688981125|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|5|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1678|1678|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|3|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|2|0.0%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[shunlist](#shunlist)|1302|1302|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|1|0.1%|0.0%|

## firehol_level1

**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5150** entries, **688981125** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3778|670299624|670299624|100.0%|97.2%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|18340608|100.0%|2.6%|
[et_block](#et_block)|999|18343755|18339907|99.9%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8867204|2.5%|1.2%|
[firehol_level3](#firehol_level3)|108574|9626093|7500199|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7498240|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4638628|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2569250|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|3574|1.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1931|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1089|1.1%|0.0%|
[sslbl](#sslbl)|380|380|380|100.0%|0.0%|
[voipbl](#voipbl)|10522|10934|334|3.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|318|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|299|2.9%|0.0%|
[firehol_level2](#firehol_level2)|26283|37939|298|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7050|7050|291|4.1%|0.0%|
[zeus](#zeus)|232|232|232|100.0%|0.0%|
[blocklist_de](#blocklist_de)|32050|32050|229|0.7%|0.0%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|0.0%|
[shunlist](#shunlist)|1302|1302|186|14.2%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|158|5.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|130|4.1%|0.0%|
[nixspam](#nixspam)|29885|29885|123|0.4%|0.0%|
[et_compromised](#et_compromised)|1678|1678|109|6.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|109|6.3%|0.0%|
[feodo](#feodo)|103|103|103|100.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|89|1.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|61|1.8%|0.0%|
[openbl_7d](#openbl_7d)|766|766|53|6.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|39|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[php_commenters](#php_commenters)|403|403|37|9.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|25|0.1%|0.0%|
[openbl_1d](#openbl_1d)|144|144|24|16.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|13|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|10|5.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|9|0.0%|0.0%|
[malc0de](#malc0de)|338|338|7|2.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|6|0.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|5|0.1%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11826|12064|3|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|3|0.0%|0.0%|
[ciarmy](#ciarmy)|451|451|3|0.6%|0.0%|
[bm_tor](#bm_tor)|6569|6569|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|2|1.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|76|76|2|2.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|1|0.1%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **26283** entries, **37939** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|32050|32050|32050|100.0%|84.4%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|19697|99.9%|51.9%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|16256|99.8%|42.8%|
[firehol_level3](#firehol_level3)|108574|9626093|7628|0.0%|20.1%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|7240|100.0%|19.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|6197|6.6%|16.3%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|5409|18.4%|14.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|4899|99.3%|12.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4375|0.0%|11.5%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|3245|99.6%|8.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|3101|99.6%|8.1%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|2797|100.0%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1786|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1674|0.0%|4.4%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|1470|0.7%|3.8%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|1314|1.5%|3.4%|
[firehol_proxies](#firehol_proxies)|11826|12064|1104|9.1%|2.9%|
[openbl_60d](#openbl_60d)|7050|7050|1088|15.4%|2.8%|
[openbl_30d](#openbl_30d)|2853|2853|869|30.4%|2.2%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|740|42.9%|1.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|702|100.0%|1.8%|
[nixspam](#nixspam)|29885|29885|673|2.2%|1.7%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|660|8.9%|1.7%|
[et_compromised](#et_compromised)|1678|1678|644|38.3%|1.6%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|579|5.7%|1.5%|
[shunlist](#shunlist)|1302|1302|467|35.8%|1.2%|
[openbl_7d](#openbl_7d)|766|766|437|57.0%|1.1%|
[proxyrss](#proxyrss)|1544|1544|378|24.4%|0.9%|
[et_tor](#et_tor)|6400|6400|352|5.5%|0.9%|
[dm_tor](#dm_tor)|6558|6558|350|5.3%|0.9%|
[bm_tor](#bm_tor)|6569|6569|348|5.2%|0.9%|
[xroxy](#xroxy)|2145|2145|336|15.6%|0.8%|
[firehol_level1](#firehol_level1)|5150|688981125|298|0.0%|0.7%|
[et_block](#et_block)|999|18343755|290|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|274|0.0%|0.7%|
[proxz](#proxz)|1158|1158|267|23.0%|0.7%|
[php_commenters](#php_commenters)|403|403|188|46.6%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|177|100.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|158|5.9%|0.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|153|41.1%|0.4%|
[openbl_1d](#openbl_1d)|144|144|144|100.0%|0.3%|
[php_dictionary](#php_dictionary)|666|666|108|16.2%|0.2%|
[php_spammers](#php_spammers)|661|661|103|15.5%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|97|0.0%|0.2%|
[dshield](#dshield)|20|5120|86|1.6%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|76|76|57|75.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|49|12.9%|0.1%|
[ciarmy](#ciarmy)|451|451|39|8.6%|0.1%|
[voipbl](#voipbl)|10522|10934|32|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|16|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|10|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|8|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **108574** entries, **9626093** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5150|688981125|7500199|1.0%|77.9%|
[et_block](#et_block)|999|18343755|6933331|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6933032|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537305|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919958|0.1%|9.5%|
[fullbogons](#fullbogons)|3778|670299624|566694|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161509|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|92512|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|29168|99.6%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|10136|100.0%|0.1%|
[firehol_level2](#firehol_level2)|26283|37939|7628|20.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|6389|7.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11826|12064|5280|43.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|5188|2.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|4837|66.8%|0.0%|
[blocklist_de](#blocklist_de)|32050|32050|3938|12.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|3547|48.2%|0.0%|
[openbl_60d](#openbl_60d)|7050|7050|2984|42.3%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|2853|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|2249|69.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|1721|100.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1625|96.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|1511|56.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[shunlist](#shunlist)|1302|1302|1302|100.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[xroxy](#xroxy)|2145|2145|1279|59.6%|0.0%|
[et_tor](#et_tor)|6400|6400|1123|17.5%|0.0%|
[bm_tor](#bm_tor)|6569|6569|1099|16.7%|0.0%|
[dm_tor](#dm_tor)|6558|6558|1096|16.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|1080|34.7%|0.0%|
[openbl_7d](#openbl_7d)|766|766|766|100.0%|0.0%|
[proxz](#proxz)|1158|1158|691|59.6%|0.0%|
[proxyrss](#proxyrss)|1544|1544|681|44.1%|0.0%|
[php_dictionary](#php_dictionary)|666|666|666|100.0%|0.0%|
[php_spammers](#php_spammers)|661|661|661|100.0%|0.0%|
[nixspam](#nixspam)|29885|29885|525|1.7%|0.0%|
[ciarmy](#ciarmy)|451|451|451|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|443|2.2%|0.0%|
[php_commenters](#php_commenters)|403|403|403|100.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|378|100.0%|0.0%|
[malc0de](#malc0de)|338|338|338|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|299|1.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|234|62.9%|0.0%|
[zeus](#zeus)|232|232|204|87.9%|0.0%|
[zeus_badips](#zeus_badips)|202|202|180|89.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|172|100.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|156|88.1%|0.0%|
[openbl_1d](#openbl_1d)|144|144|141|97.9%|0.0%|
[dshield](#dshield)|20|5120|122|2.3%|0.0%|
[sslbl](#sslbl)|380|380|96|25.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|92|1.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|88|0.0%|0.0%|
[feodo](#feodo)|103|103|81|78.6%|0.0%|
[voipbl](#voipbl)|10522|10934|57|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|47|1.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|23|3.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|21|0.0%|0.0%|
[virbl](#virbl)|20|20|20|100.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|17|2.4%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|3|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|76|76|3|3.9%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **11826** entries, **12064** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18450|82472|12064|14.6%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|7349|100.0%|60.9%|
[firehol_level3](#firehol_level3)|108574|9626093|5280|0.0%|43.7%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|5219|5.6%|43.2%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|2661|100.0%|22.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2400|8.1%|19.8%|
[xroxy](#xroxy)|2145|2145|2145|100.0%|17.7%|
[proxyrss](#proxyrss)|1544|1544|1544|100.0%|12.7%|
[proxz](#proxz)|1158|1158|1158|100.0%|9.5%|
[firehol_level2](#firehol_level2)|26283|37939|1104|2.9%|9.1%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|801|11.0%|6.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.4%|
[blocklist_de](#blocklist_de)|32050|32050|592|1.8%|4.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|496|0.0%|4.1%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|494|15.1%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|378|0.0%|3.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|275|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|251|2.4%|2.0%|
[et_tor](#et_tor)|6400|6400|168|2.6%|1.3%|
[dm_tor](#dm_tor)|6558|6558|167|2.5%|1.3%|
[bm_tor](#bm_tor)|6569|6569|165|2.5%|1.3%|
[nixspam](#nixspam)|29885|29885|153|0.5%|1.2%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|91|0.4%|0.7%|
[php_dictionary](#php_dictionary)|666|666|86|12.9%|0.7%|
[php_spammers](#php_spammers)|661|661|71|10.7%|0.5%|
[php_commenters](#php_commenters)|403|403|69|17.1%|0.5%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|34|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7050|7050|18|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|16|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|11|2.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|8|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|7|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|5|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[firehol_level1](#firehol_level1)|5150|688981125|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|3|0.1%|0.0%|
[et_block](#et_block)|999|18343755|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|3|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|2|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[shunlist](#shunlist)|1302|1302|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5150|688981125|670299624|97.2%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4237167|3.0%|0.6%|
[firehol_level3](#firehol_level3)|108574|9626093|566694|5.8%|0.0%|
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
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[nixspam](#nixspam)|29885|29885|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|1|0.5%|0.0%|
[ciarmy](#ciarmy)|451|451|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|108574|9626093|21|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5150|688981125|18|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11826|12064|16|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|16|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|15|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|13|0.0%|0.0%|
[fullbogons](#fullbogons)|3778|670299624|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[nixspam](#nixspam)|29885|29885|10|0.0%|0.0%|
[et_block](#et_block)|999|18343755|9|0.0%|0.0%|
[firehol_level2](#firehol_level2)|26283|37939|8|0.0%|0.0%|
[blocklist_de](#blocklist_de)|32050|32050|8|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|5|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|4|0.0%|0.0%|
[xroxy](#xroxy)|2145|2145|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|3|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|1|0.0%|0.0%|
[proxz](#proxz)|1158|1158|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1544|1544|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|108574|9626093|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5150|688981125|7498240|1.0%|81.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6932480|37.7%|75.5%|
[et_block](#et_block)|999|18343755|6932480|37.7%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3778|670299624|565760|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|719|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|518|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|157|0.5%|0.0%|
[nixspam](#nixspam)|29885|29885|121|0.4%|0.0%|
[firehol_level2](#firehol_level2)|26283|37939|97|0.2%|0.0%|
[blocklist_de](#blocklist_de)|32050|32050|60|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|50|1.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|43|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|7050|7050|17|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|12|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
[zeus](#zeus)|232|232|10|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|7|0.0%|0.0%|
[openbl_7d](#openbl_7d)|766|766|5|0.6%|0.0%|
[et_compromised](#et_compromised)|1678|1678|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|5|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|5|0.1%|0.0%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6569|6569|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|4|0.0%|0.0%|
[shunlist](#shunlist)|1302|1302|3|0.2%|0.0%|
[php_spammers](#php_spammers)|661|661|3|0.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|3|0.1%|0.0%|
[openbl_1d](#openbl_1d)|144|144|2|1.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11826|12064|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.0%|
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
[firehol_level1](#firehol_level1)|5150|688981125|2569250|0.3%|0.3%|
[et_block](#et_block)|999|18343755|2272541|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|108574|9626093|919958|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3778|670299624|263817|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|4218|2.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|3422|4.1%|0.0%|
[firehol_level2](#firehol_level2)|26283|37939|1674|4.4%|0.0%|
[blocklist_de](#blocklist_de)|32050|32050|1559|4.8%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1506|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|1403|7.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|1337|8.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|549|1.8%|0.0%|
[nixspam](#nixspam)|29885|29885|497|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[voipbl](#voipbl)|10522|10934|299|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11826|12064|275|2.2%|0.0%|
[et_tor](#et_tor)|6400|6400|166|2.5%|0.0%|
[dm_tor](#dm_tor)|6558|6558|166|2.5%|0.0%|
[bm_tor](#bm_tor)|6569|6569|165|2.5%|0.0%|
[openbl_60d](#openbl_60d)|7050|7050|162|2.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|147|2.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|130|1.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|118|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|80|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|63|2.2%|0.0%|
[xroxy](#xroxy)|2145|2145|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|54|1.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|52|3.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|46|2.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|45|0.9%|0.0%|
[et_botcc](#et_botcc)|509|509|40|7.8%|0.0%|
[proxz](#proxz)|1158|1158|39|3.3%|0.0%|
[proxyrss](#proxyrss)|1544|1544|38|2.4%|0.0%|
[ciarmy](#ciarmy)|451|451|38|8.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|35|1.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|30|1.0%|0.0%|
[shunlist](#shunlist)|1302|1302|26|1.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[openbl_7d](#openbl_7d)|766|766|16|2.0%|0.0%|
[php_dictionary](#php_dictionary)|666|666|12|1.8%|0.0%|
[php_harvesters](#php_harvesters)|378|378|11|2.9%|0.0%|
[malc0de](#malc0de)|338|338|11|3.2%|0.0%|
[php_spammers](#php_spammers)|661|661|10|1.5%|0.0%|
[php_commenters](#php_commenters)|403|403|10|2.4%|0.0%|
[zeus](#zeus)|232|232|7|3.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|7|0.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|76|76|6|7.8%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|4|1.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|4|2.3%|0.0%|
[sslbl](#sslbl)|380|380|3|0.7%|0.0%|
[feodo](#feodo)|103|103|3|2.9%|0.0%|
[virbl](#virbl)|20|20|1|5.0%|0.0%|
[openbl_1d](#openbl_1d)|144|144|1|0.6%|0.0%|

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
[firehol_level1](#firehol_level1)|5150|688981125|8867204|1.2%|2.5%|
[et_block](#et_block)|999|18343755|8533288|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|108574|9626093|2537305|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3778|670299624|252159|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|6261|3.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|2880|3.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2475|2.6%|0.0%|
[firehol_level2](#firehol_level2)|26283|37939|1786|4.7%|0.0%|
[blocklist_de](#blocklist_de)|32050|32050|1621|5.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|1274|6.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|1107|6.7%|0.0%|
[nixspam](#nixspam)|29885|29885|1102|3.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|825|2.8%|0.0%|
[voipbl](#voipbl)|10522|10934|434|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|11826|12064|378|3.1%|0.0%|
[openbl_60d](#openbl_60d)|7050|7050|322|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|215|2.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|212|2.9%|0.0%|
[et_tor](#et_tor)|6400|6400|186|2.9%|0.0%|
[dm_tor](#dm_tor)|6558|6558|182|2.7%|0.0%|
[bm_tor](#bm_tor)|6569|6569|182|2.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|167|1.6%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|150|5.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|137|4.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|111|3.4%|0.0%|
[xroxy](#xroxy)|2145|2145|104|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|102|3.8%|0.0%|
[et_compromised](#et_compromised)|1678|1678|86|5.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|84|4.8%|0.0%|
[shunlist](#shunlist)|1302|1302|74|5.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|72|1.4%|0.0%|
[proxyrss](#proxyrss)|1544|1544|67|4.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|55|1.9%|0.0%|
[php_spammers](#php_spammers)|661|661|52|7.8%|0.0%|
[proxz](#proxz)|1158|1158|47|4.0%|0.0%|
[ciarmy](#ciarmy)|451|451|47|10.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[openbl_7d](#openbl_7d)|766|766|43|5.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[php_dictionary](#php_dictionary)|666|666|22|3.3%|0.0%|
[et_botcc](#et_botcc)|509|509|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[malc0de](#malc0de)|338|338|19|5.6%|0.0%|
[php_commenters](#php_commenters)|403|403|16|3.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|12|1.7%|0.0%|
[zeus](#zeus)|232|232|9|3.8%|0.0%|
[php_harvesters](#php_harvesters)|378|378|9|2.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|8|3.9%|0.0%|
[openbl_1d](#openbl_1d)|144|144|7|4.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|7|3.9%|0.0%|
[sslbl](#sslbl)|380|380|6|1.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|76|76|6|7.8%|0.0%|
[feodo](#feodo)|103|103|3|2.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|3|1.7%|0.0%|
[virbl](#virbl)|20|20|2|10.0%|0.0%|
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
[firehol_level1](#firehol_level1)|5150|688981125|4638628|0.6%|3.3%|
[fullbogons](#fullbogons)|3778|670299624|4237167|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|108574|9626093|161509|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|999|18343755|130394|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|14134|7.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|5744|6.2%|0.0%|
[firehol_level2](#firehol_level2)|26283|37939|4375|11.5%|0.0%|
[blocklist_de](#blocklist_de)|32050|32050|3927|12.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|2842|3.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|2821|14.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|2432|14.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1893|6.4%|0.0%|
[voipbl](#voipbl)|10522|10934|1602|14.6%|0.0%|
[nixspam](#nixspam)|29885|29885|1400|4.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7050|7050|743|10.5%|0.0%|
[et_tor](#et_tor)|6400|6400|623|9.7%|0.0%|
[bm_tor](#bm_tor)|6569|6569|619|9.4%|0.0%|
[dm_tor](#dm_tor)|6558|6558|616|9.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|523|7.2%|0.0%|
[firehol_proxies](#firehol_proxies)|11826|12064|496|4.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|412|13.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|337|6.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|316|11.2%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|294|10.3%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|253|2.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|210|6.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|209|2.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|153|8.8%|0.0%|
[et_compromised](#et_compromised)|1678|1678|151|8.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[shunlist](#shunlist)|1302|1302|118|9.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[xroxy](#xroxy)|2145|2145|107|4.9%|0.0%|
[proxz](#proxz)|1158|1158|98|8.4%|0.0%|
[ciarmy](#ciarmy)|451|451|98|21.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|97|13.8%|0.0%|
[openbl_7d](#openbl_7d)|766|766|92|12.0%|0.0%|
[et_botcc](#et_botcc)|509|509|80|15.7%|0.0%|
[proxyrss](#proxyrss)|1544|1544|57|3.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|56|2.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[malc0de](#malc0de)|338|338|46|13.6%|0.0%|
[php_spammers](#php_spammers)|661|661|41|6.2%|0.0%|
[php_dictionary](#php_dictionary)|666|666|35|5.2%|0.0%|
[sslbl](#sslbl)|380|380|30|7.8%|0.0%|
[php_commenters](#php_commenters)|403|403|25|6.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|22|12.7%|0.0%|
[php_harvesters](#php_harvesters)|378|378|20|5.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|17|9.6%|0.0%|
[zeus](#zeus)|232|232|14|6.0%|0.0%|
[openbl_1d](#openbl_1d)|144|144|14|9.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|76|76|13|17.1%|0.0%|
[feodo](#feodo)|103|103|11|10.6%|0.0%|
[zeus_badips](#zeus_badips)|202|202|10|4.9%|0.0%|
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
[firehol_proxies](#firehol_proxies)|11826|12064|663|5.4%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|663|0.8%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|108574|9626093|23|0.0%|3.4%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|18|0.0%|2.7%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|14|0.1%|2.1%|
[xroxy](#xroxy)|2145|2145|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|13|0.0%|1.9%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|7|0.2%|1.0%|
[proxyrss](#proxyrss)|1544|1544|7|0.4%|1.0%|
[proxz](#proxz)|1158|1158|6|0.5%|0.9%|
[firehol_level2](#firehol_level2)|26283|37939|6|0.0%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|5|0.0%|0.7%|
[blocklist_de](#blocklist_de)|32050|32050|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5150|688981125|2|0.0%|0.3%|
[et_block](#et_block)|999|18343755|2|0.0%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|2|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|666|666|1|0.1%|0.1%|
[nixspam](#nixspam)|29885|29885|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|1|0.0%|0.1%|

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
[firehol_level3](#firehol_level3)|108574|9626093|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5150|688981125|1931|0.0%|0.5%|
[et_block](#et_block)|999|18343755|1041|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3778|670299624|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|48|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|28|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|22|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6558|6558|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6569|6569|22|0.3%|0.0%|
[nixspam](#nixspam)|29885|29885|20|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[firehol_level2](#firehol_level2)|26283|37939|16|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|15|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|11826|12064|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|10|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|6|0.0%|0.0%|
[blocklist_de](#blocklist_de)|32050|32050|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7050|7050|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10522|10934|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|3|0.1%|0.0%|
[malc0de](#malc0de)|338|338|3|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|3|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|3|0.0%|0.0%|
[proxyrss](#proxyrss)|1544|1544|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|76|76|2|2.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[xroxy](#xroxy)|2145|2145|1|0.0%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|1|0.0%|0.0%|
[proxz](#proxz)|1158|1158|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|666|666|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[feodo](#feodo)|103|103|1|0.9%|0.0%|
[ciarmy](#ciarmy)|451|451|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|108574|9626093|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5150|688981125|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3778|670299624|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|10|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.4%|
[et_block](#et_block)|999|18343755|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|11826|12064|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7050|7050|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2853|2853|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[firehol_level2](#firehol_level2)|26283|37939|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|766|766|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|32050|32050|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|108574|9626093|338|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|46|0.0%|13.6%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|20|11.6%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|19|0.0%|5.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.2%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|11|0.0%|3.2%|
[firehol_level1](#firehol_level1)|5150|688981125|7|0.0%|2.0%|
[et_block](#et_block)|999|18343755|5|0.0%|1.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|1.1%|
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
[firehol_level3](#firehol_level3)|108574|9626093|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5150|688981125|39|0.0%|3.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|2.2%|
[et_block](#et_block)|999|18343755|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|13|0.1%|1.0%|
[fullbogons](#fullbogons)|3778|670299624|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|7|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|4|0.0%|0.3%|
[malc0de](#malc0de)|338|338|4|1.1%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.0%|
[nixspam](#nixspam)|29885|29885|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|1|0.5%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Tue Jun  9 17:45:09 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11826|12064|372|3.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|372|0.4%|100.0%|
[firehol_level3](#firehol_level3)|108574|9626093|234|0.0%|62.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|233|0.2%|62.6%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|192|0.6%|51.6%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|171|1.6%|45.9%|
[et_tor](#et_tor)|6400|6400|165|2.5%|44.3%|
[dm_tor](#dm_tor)|6558|6558|163|2.4%|43.8%|
[bm_tor](#bm_tor)|6569|6569|163|2.4%|43.8%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|153|2.1%|41.1%|
[firehol_level2](#firehol_level2)|26283|37939|153|0.4%|41.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|125|0.0%|33.6%|
[php_commenters](#php_commenters)|403|403|44|10.9%|11.8%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7050|7050|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|378|378|6|1.5%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|4|0.0%|1.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|1.0%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|1.0%|
[xroxy](#xroxy)|2145|2145|1|0.0%|0.2%|
[voipbl](#voipbl)|10522|10934|1|0.0%|0.2%|
[shunlist](#shunlist)|1302|1302|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|1|0.0%|0.2%|
[nixspam](#nixspam)|29885|29885|1|0.0%|0.2%|
[et_block](#et_block)|999|18343755|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|32050|32050|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Tue Jun  9 21:30:02 UTC 2015.

The ipset `nixspam` has **29885** entries, **29885** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1400|0.0%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1102|0.0%|3.6%|
[firehol_level2](#firehol_level2)|26283|37939|673|1.7%|2.2%|
[blocklist_de](#blocklist_de)|32050|32050|657|2.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|566|2.8%|1.8%|
[firehol_level3](#firehol_level3)|108574|9626093|525|0.0%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|497|0.0%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|218|0.2%|0.7%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|173|1.7%|0.5%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|159|0.1%|0.5%|
[firehol_proxies](#firehol_proxies)|11826|12064|153|1.2%|0.5%|
[firehol_level1](#firehol_level1)|5150|688981125|123|0.0%|0.4%|
[et_block](#et_block)|999|18343755|123|0.0%|0.4%|
[php_dictionary](#php_dictionary)|666|666|122|18.3%|0.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|121|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|121|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|110|0.3%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|109|1.4%|0.3%|
[php_spammers](#php_spammers)|661|661|107|16.1%|0.3%|
[xroxy](#xroxy)|2145|2145|65|3.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|64|0.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|59|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|43|0.2%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|42|0.8%|0.1%|
[proxz](#proxz)|1158|1158|40|3.4%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|30|0.9%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|29|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|20|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|11|0.3%|0.0%|
[php_commenters](#php_commenters)|403|403|10|2.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|10|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|9|2.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|8|0.3%|0.0%|
[proxyrss](#proxyrss)|1544|1544|8|0.5%|0.0%|
[openbl_60d](#openbl_60d)|7050|7050|7|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|5|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6569|6569|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|4|0.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|3|1.6%|0.0%|
[voipbl](#voipbl)|10522|10934|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[shunlist](#shunlist)|1302|1302|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|766|766|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Tue Jun  9 21:32:00 UTC 2015.

The ipset `openbl_1d` has **144** entries, **144** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26283|37939|144|0.3%|100.0%|
[openbl_60d](#openbl_60d)|7050|7050|141|2.0%|97.9%|
[openbl_30d](#openbl_30d)|2853|2853|141|4.9%|97.9%|
[firehol_level3](#firehol_level3)|108574|9626093|141|0.0%|97.9%|
[openbl_7d](#openbl_7d)|766|766|140|18.2%|97.2%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|134|0.0%|93.0%|
[blocklist_de](#blocklist_de)|32050|32050|119|0.3%|82.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|117|3.7%|81.2%|
[shunlist](#shunlist)|1302|1302|67|5.1%|46.5%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|61|3.5%|42.3%|
[et_compromised](#et_compromised)|1678|1678|55|3.2%|38.1%|
[et_block](#et_block)|999|18343755|26|0.0%|18.0%|
[firehol_level1](#firehol_level1)|5150|688981125|24|0.0%|16.6%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|23|0.0%|15.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|16|9.0%|11.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|9.7%|
[dshield](#dshield)|20|5120|10|0.1%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|4.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|1.3%|
[ciarmy](#ciarmy)|451|451|2|0.4%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1|0.0%|0.6%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.6%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|1|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|1|0.0%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|1|0.0%|0.6%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Tue Jun  9 20:07:00 UTC 2015.

The ipset `openbl_30d` has **2853** entries, **2853** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7050|7050|2853|40.4%|100.0%|
[firehol_level3](#firehol_level3)|108574|9626093|2853|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|2832|1.5%|99.2%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|942|54.7%|33.0%|
[et_compromised](#et_compromised)|1678|1678|916|54.5%|32.1%|
[firehol_level2](#firehol_level2)|26283|37939|869|2.2%|30.4%|
[blocklist_de](#blocklist_de)|32050|32050|847|2.6%|29.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|805|25.8%|28.2%|
[openbl_7d](#openbl_7d)|766|766|766|100.0%|26.8%|
[shunlist](#shunlist)|1302|1302|536|41.1%|18.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|294|0.0%|10.3%|
[firehol_level1](#firehol_level1)|5150|688981125|158|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|150|0.0%|5.2%|
[openbl_1d](#openbl_1d)|144|144|141|97.9%|4.9%|
[et_block](#et_block)|999|18343755|128|0.0%|4.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|121|0.0%|4.2%|
[dshield](#dshield)|20|5120|104|2.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|63|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|35|0.1%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|28|1.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|24|13.5%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|5|0.0%|0.1%|
[nixspam](#nixspam)|29885|29885|5|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|4|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|4|0.0%|0.1%|
[voipbl](#voipbl)|10522|10934|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|451|451|2|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|2|0.2%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Tue Jun  9 20:07:00 UTC 2015.

The ipset `openbl_60d` has **7050** entries, **7050** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|184826|184826|7023|3.7%|99.6%|
[firehol_level3](#firehol_level3)|108574|9626093|2984|0.0%|42.3%|
[openbl_30d](#openbl_30d)|2853|2853|2853|100.0%|40.4%|
[firehol_level2](#firehol_level2)|26283|37939|1088|2.8%|15.4%|
[blocklist_de](#blocklist_de)|32050|32050|1047|3.2%|14.8%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|1002|58.2%|14.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|990|31.8%|14.0%|
[et_compromised](#et_compromised)|1678|1678|982|58.5%|13.9%|
[openbl_7d](#openbl_7d)|766|766|766|100.0%|10.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|743|0.0%|10.5%|
[shunlist](#shunlist)|1302|1302|565|43.3%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|322|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5150|688981125|291|0.0%|4.1%|
[et_block](#et_block)|999|18343755|248|0.0%|3.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|236|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|162|0.0%|2.2%|
[openbl_1d](#openbl_1d)|144|144|141|97.9%|2.0%|
[dshield](#dshield)|20|5120|121|2.3%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|49|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|42|0.2%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|33|1.1%|0.4%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|27|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|25|14.1%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|24|0.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|23|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|20|0.2%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6558|6558|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6569|6569|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[firehol_proxies](#firehol_proxies)|11826|12064|18|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|17|0.0%|0.2%|
[php_commenters](#php_commenters)|403|403|11|2.7%|0.1%|
[voipbl](#voipbl)|10522|10934|8|0.0%|0.1%|
[nixspam](#nixspam)|29885|29885|7|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|6|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|4|0.0%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ciarmy](#ciarmy)|451|451|2|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Tue Jun  9 20:07:00 UTC 2015.

The ipset `openbl_7d` has **766** entries, **766** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7050|7050|766|10.8%|100.0%|
[openbl_30d](#openbl_30d)|2853|2853|766|26.8%|100.0%|
[firehol_level3](#firehol_level3)|108574|9626093|766|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|756|0.4%|98.6%|
[firehol_level2](#firehol_level2)|26283|37939|437|1.1%|57.0%|
[blocklist_de](#blocklist_de)|32050|32050|415|1.2%|54.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|405|13.0%|52.8%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|328|19.0%|42.8%|
[et_compromised](#et_compromised)|1678|1678|309|18.4%|40.3%|
[shunlist](#shunlist)|1302|1302|229|17.5%|29.8%|
[openbl_1d](#openbl_1d)|144|144|140|97.2%|18.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|92|0.0%|12.0%|
[et_block](#et_block)|999|18343755|56|0.0%|7.3%|
[firehol_level1](#firehol_level1)|5150|688981125|53|0.0%|6.9%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|50|0.0%|6.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|43|0.0%|5.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|23|12.9%|3.0%|
[dshield](#dshield)|20|5120|18|0.3%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|16|0.0%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|9|0.0%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|9|0.3%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|3|0.0%|0.3%|
[ciarmy](#ciarmy)|451|451|2|0.4%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|1|0.0%|0.1%|
[php_spammers](#php_spammers)|661|661|1|0.1%|0.1%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.1%|
[nixspam](#nixspam)|29885|29885|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|1|0.1%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  9 21:36:21 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5150|688981125|13|0.0%|100.0%|
[et_block](#et_block)|999|18343755|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|108574|9626093|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Tue Jun  9 21:45:17 UTC 2015.

The ipset `php_commenters` has **403** entries, **403** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108574|9626093|403|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|301|0.3%|74.6%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|227|0.7%|56.3%|
[firehol_level2](#firehol_level2)|26283|37939|188|0.4%|46.6%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|161|2.2%|39.9%|
[blocklist_de](#blocklist_de)|32050|32050|98|0.3%|24.3%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|77|2.3%|19.1%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|76|0.0%|18.8%|
[firehol_proxies](#firehol_proxies)|11826|12064|69|0.5%|17.1%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|59|0.5%|14.6%|
[et_tor](#et_tor)|6400|6400|48|0.7%|11.9%|
[dm_tor](#dm_tor)|6558|6558|48|0.7%|11.9%|
[bm_tor](#bm_tor)|6569|6569|48|0.7%|11.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|45|25.4%|11.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|44|11.8%|10.9%|
[php_spammers](#php_spammers)|661|661|43|6.5%|10.6%|
[firehol_level1](#firehol_level1)|5150|688981125|37|0.0%|9.1%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|32|0.1%|7.9%|
[et_block](#et_block)|999|18343755|30|0.0%|7.4%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|29|0.0%|7.1%|
[php_dictionary](#php_dictionary)|666|666|28|4.2%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|25|0.0%|6.2%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|25|0.1%|6.2%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|23|0.3%|5.7%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|18|0.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16|0.0%|3.9%|
[php_harvesters](#php_harvesters)|378|378|15|3.9%|3.7%|
[openbl_60d](#openbl_60d)|7050|7050|11|0.1%|2.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|11|0.2%|2.7%|
[nixspam](#nixspam)|29885|29885|10|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.4%|
[xroxy](#xroxy)|2145|2145|8|0.3%|1.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|1.7%|
[proxz](#proxz)|1158|1158|7|0.6%|1.7%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|5|0.1%|1.2%|
[proxyrss](#proxyrss)|1544|1544|2|0.1%|0.4%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.2%|
[zeus](#zeus)|232|232|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|766|766|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2853|2853|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|144|144|1|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Tue Jun  9 21:45:18 UTC 2015.

The ipset `php_dictionary` has **666** entries, **666** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108574|9626093|666|0.0%|100.0%|
[php_spammers](#php_spammers)|661|661|273|41.3%|40.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|125|0.1%|18.7%|
[nixspam](#nixspam)|29885|29885|122|0.4%|18.3%|
[firehol_level2](#firehol_level2)|26283|37939|108|0.2%|16.2%|
[blocklist_de](#blocklist_de)|32050|32050|101|0.3%|15.1%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|87|0.1%|13.0%|
[firehol_proxies](#firehol_proxies)|11826|12064|86|0.7%|12.9%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|83|0.8%|12.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|81|0.2%|12.1%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|79|0.4%|11.8%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|58|0.7%|8.7%|
[xroxy](#xroxy)|2145|2145|39|1.8%|5.8%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|37|0.5%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|35|0.0%|5.2%|
[php_commenters](#php_commenters)|403|403|28|6.9%|4.2%|
[proxz](#proxz)|1158|1158|23|1.9%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|22|0.0%|3.3%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|17|0.5%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|12|0.0%|1.8%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|8|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|6|0.0%|0.9%|
[firehol_level1](#firehol_level1)|5150|688981125|6|0.0%|0.9%|
[et_block](#et_block)|999|18343755|6|0.0%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|5|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|5|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|4|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|4|2.2%|0.6%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.4%|
[dm_tor](#dm_tor)|6558|6558|3|0.0%|0.4%|
[bm_tor](#bm_tor)|6569|6569|3|0.0%|0.4%|
[proxyrss](#proxyrss)|1544|1544|2|0.1%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Tue Jun  9 21:45:13 UTC 2015.

The ipset `php_harvesters` has **378** entries, **378** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108574|9626093|378|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|81|0.0%|21.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|61|0.2%|16.1%|
[firehol_level2](#firehol_level2)|26283|37939|49|0.1%|12.9%|
[blocklist_de](#blocklist_de)|32050|32050|37|0.1%|9.7%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|35|0.4%|9.2%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|29|0.8%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|20|0.0%|5.2%|
[php_commenters](#php_commenters)|403|403|15|3.7%|3.9%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|12|0.0%|3.1%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|11|0.1%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|2.9%|
[firehol_proxies](#firehol_proxies)|11826|12064|11|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|11|0.0%|2.9%|
[nixspam](#nixspam)|29885|29885|9|0.0%|2.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.3%|
[et_tor](#et_tor)|6400|6400|7|0.1%|1.8%|
[dm_tor](#dm_tor)|6558|6558|7|0.1%|1.8%|
[bm_tor](#bm_tor)|6569|6569|7|0.1%|1.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|5|0.0%|1.3%|
[php_spammers](#php_spammers)|661|661|3|0.4%|0.7%|
[php_dictionary](#php_dictionary)|666|666|3|0.4%|0.7%|
[firehol_level1](#firehol_level1)|5150|688981125|3|0.0%|0.7%|
[xroxy](#xroxy)|2145|2145|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|2|0.0%|0.5%|
[proxyrss](#proxyrss)|1544|1544|2|0.1%|0.5%|
[openbl_60d](#openbl_60d)|7050|7050|2|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|2|0.2%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.2%|
[et_block](#et_block)|999|18343755|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Tue Jun  9 21:45:16 UTC 2015.

The ipset `php_spammers` has **661** entries, **661** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108574|9626093|661|0.0%|100.0%|
[php_dictionary](#php_dictionary)|666|666|273|40.9%|41.3%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|136|0.1%|20.5%|
[nixspam](#nixspam)|29885|29885|107|0.3%|16.1%|
[firehol_level2](#firehol_level2)|26283|37939|103|0.2%|15.5%|
[blocklist_de](#blocklist_de)|32050|32050|94|0.2%|14.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|80|0.2%|12.1%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|78|0.7%|11.8%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|73|0.0%|11.0%|
[firehol_proxies](#firehol_proxies)|11826|12064|71|0.5%|10.7%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|67|0.3%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|52|0.0%|7.8%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|48|0.6%|7.2%|
[php_commenters](#php_commenters)|403|403|43|10.6%|6.5%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|42|0.5%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|41|0.0%|6.2%|
[xroxy](#xroxy)|2145|2145|32|1.4%|4.8%|
[proxz](#proxz)|1158|1158|21|1.8%|3.1%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|19|0.5%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|7|3.9%|1.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|7|0.1%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|7|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|5|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|4|0.0%|0.6%|
[proxyrss](#proxyrss)|1544|1544|4|0.2%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[firehol_level1](#firehol_level1)|5150|688981125|4|0.0%|0.6%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.6%|
[et_block](#et_block)|999|18343755|4|0.0%|0.6%|
[dm_tor](#dm_tor)|6558|6558|4|0.0%|0.6%|
[bm_tor](#bm_tor)|6569|6569|4|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|3|0.1%|0.4%|
[php_harvesters](#php_harvesters)|378|378|3|0.7%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[openbl_7d](#openbl_7d)|766|766|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7050|7050|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2853|2853|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|144|144|1|0.6%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Tue Jun  9 18:21:39 UTC 2015.

The ipset `proxyrss` has **1544** entries, **1544** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11826|12064|1544|12.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|1544|1.8%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|681|0.7%|44.1%|
[firehol_level3](#firehol_level3)|108574|9626093|681|0.0%|44.1%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|610|8.3%|39.5%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|532|1.8%|34.4%|
[xroxy](#xroxy)|2145|2145|387|18.0%|25.0%|
[firehol_level2](#firehol_level2)|26283|37939|378|0.9%|24.4%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|311|4.2%|20.1%|
[proxz](#proxz)|1158|1158|260|22.4%|16.8%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|220|8.2%|14.2%|
[blocklist_de](#blocklist_de)|32050|32050|204|0.6%|13.2%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|203|6.2%|13.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|67|0.0%|4.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|57|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|38|0.0%|2.4%|
[nixspam](#nixspam)|29885|29885|8|0.0%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|5|0.0%|0.3%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|4|2.2%|0.2%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.1%|
[php_dictionary](#php_dictionary)|666|666|2|0.3%|0.1%|
[php_commenters](#php_commenters)|403|403|2|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Tue Jun  9 20:51:41 UTC 2015.

The ipset `proxz` has **1158** entries, **1158** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11826|12064|1158|9.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|1158|1.4%|100.0%|
[firehol_level3](#firehol_level3)|108574|9626093|691|0.0%|59.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|685|0.7%|59.1%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|532|7.2%|45.9%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|493|1.6%|42.5%|
[xroxy](#xroxy)|2145|2145|420|19.5%|36.2%|
[firehol_level2](#firehol_level2)|26283|37939|267|0.7%|23.0%|
[proxyrss](#proxyrss)|1544|1544|260|16.8%|22.4%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|200|2.7%|17.2%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|195|7.3%|16.8%|
[blocklist_de](#blocklist_de)|32050|32050|172|0.5%|14.8%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|147|4.5%|12.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|98|0.0%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|47|0.0%|4.0%|
[nixspam](#nixspam)|29885|29885|40|0.1%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|39|0.0%|3.3%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|25|0.1%|2.1%|
[php_dictionary](#php_dictionary)|666|666|23|3.4%|1.9%|
[php_spammers](#php_spammers)|661|661|21|3.1%|1.8%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|20|0.1%|1.7%|
[php_commenters](#php_commenters)|403|403|7|1.7%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|4|2.2%|0.3%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|3|0.0%|0.2%|
[et_compromised](#et_compromised)|1678|1678|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Tue Jun  9 14:11:14 UTC 2015.

The ipset `ri_connect_proxies` has **2661** entries, **2661** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11826|12064|2661|22.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|2661|3.2%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1511|1.6%|56.7%|
[firehol_level3](#firehol_level3)|108574|9626093|1511|0.0%|56.7%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|1131|15.3%|42.5%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|622|2.1%|23.3%|
[xroxy](#xroxy)|2145|2145|384|17.9%|14.4%|
[proxyrss](#proxyrss)|1544|1544|220|14.2%|8.2%|
[proxz](#proxz)|1158|1158|195|16.8%|7.3%|
[firehol_level2](#firehol_level2)|26283|37939|158|0.4%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|117|1.6%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|102|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|80|0.0%|3.0%|
[blocklist_de](#blocklist_de)|32050|32050|70|0.2%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|67|2.0%|2.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|56|0.0%|2.1%|
[nixspam](#nixspam)|29885|29885|8|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|5|0.0%|0.1%|
[php_commenters](#php_commenters)|403|403|5|1.2%|0.1%|
[php_dictionary](#php_dictionary)|666|666|4|0.6%|0.1%|
[php_spammers](#php_spammers)|661|661|3|0.4%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|3|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Tue Jun  9 20:49:05 UTC 2015.

The ipset `ri_web_proxies` has **7349** entries, **7349** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11826|12064|7349|60.9%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|7349|8.9%|100.0%|
[firehol_level3](#firehol_level3)|108574|9626093|3547|0.0%|48.2%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|3500|3.7%|47.6%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1595|5.4%|21.7%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|1131|42.5%|15.3%|
[xroxy](#xroxy)|2145|2145|940|43.8%|12.7%|
[firehol_level2](#firehol_level2)|26283|37939|660|1.7%|8.9%|
[proxyrss](#proxyrss)|1544|1544|610|39.5%|8.3%|
[proxz](#proxz)|1158|1158|532|45.9%|7.2%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|471|6.5%|6.4%|
[blocklist_de](#blocklist_de)|32050|32050|412|1.2%|5.6%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|349|10.7%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|215|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|209|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|147|0.0%|2.0%|
[nixspam](#nixspam)|29885|29885|109|0.3%|1.4%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|59|0.5%|0.8%|
[php_dictionary](#php_dictionary)|666|666|58|8.7%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|56|0.2%|0.7%|
[php_spammers](#php_spammers)|661|661|48|7.2%|0.6%|
[php_commenters](#php_commenters)|403|403|23|5.7%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|14|2.1%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|7|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|7|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|6|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|4|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[bm_tor](#bm_tor)|6569|6569|2|0.0%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5150|688981125|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Tue Jun  9 19:30:33 UTC 2015.

The ipset `shunlist` has **1302** entries, **1302** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108574|9626093|1302|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|1273|0.6%|97.7%|
[openbl_60d](#openbl_60d)|7050|7050|565|8.0%|43.3%|
[openbl_30d](#openbl_30d)|2853|2853|536|18.7%|41.1%|
[firehol_level2](#firehol_level2)|26283|37939|467|1.2%|35.8%|
[blocklist_de](#blocklist_de)|32050|32050|464|1.4%|35.6%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|444|25.7%|34.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|428|13.7%|32.8%|
[et_compromised](#et_compromised)|1678|1678|419|24.9%|32.1%|
[openbl_7d](#openbl_7d)|766|766|229|29.8%|17.5%|
[firehol_level1](#firehol_level1)|5150|688981125|186|0.0%|14.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|118|0.0%|9.0%|
[et_block](#et_block)|999|18343755|105|0.0%|8.0%|
[dshield](#dshield)|20|5120|98|1.9%|7.5%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|97|0.0%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|74|0.0%|5.6%|
[openbl_1d](#openbl_1d)|144|144|67|46.5%|5.1%|
[sslbl](#sslbl)|380|380|64|16.8%|4.9%|
[ciarmy](#ciarmy)|451|451|33|7.3%|2.5%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|31|0.1%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|26|0.0%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|21|11.8%|1.6%|
[voipbl](#voipbl)|10522|10934|13|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|4|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|3|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|2|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|1|0.0%|0.0%|
[nixspam](#nixspam)|29885|29885|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[firehol_proxies](#firehol_proxies)|11826|12064|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6569|6569|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|76|76|1|1.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Tue Jun  9 16:00:00 UTC 2015.

The ipset `snort_ipfilter` has **10136** entries, **10136** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108574|9626093|10136|0.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|1154|1.3%|11.3%|
[et_tor](#et_tor)|6400|6400|1084|16.9%|10.6%|
[bm_tor](#bm_tor)|6569|6569|1060|16.1%|10.4%|
[dm_tor](#dm_tor)|6558|6558|1056|16.1%|10.4%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|797|0.8%|7.8%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|652|2.2%|6.4%|
[firehol_level2](#firehol_level2)|26283|37939|579|1.5%|5.7%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|392|5.4%|3.8%|
[firehol_level1](#firehol_level1)|5150|688981125|299|0.0%|2.9%|
[et_block](#et_block)|999|18343755|299|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|253|0.0%|2.4%|
[firehol_proxies](#firehol_proxies)|11826|12064|251|2.0%|2.4%|
[blocklist_de](#blocklist_de)|32050|32050|233|0.7%|2.2%|
[zeus](#zeus)|232|232|201|86.6%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|187|0.9%|1.8%|
[zeus_badips](#zeus_badips)|202|202|178|88.1%|1.7%|
[nixspam](#nixspam)|29885|29885|173|0.5%|1.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|171|45.9%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|167|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|118|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|118|0.0%|1.1%|
[php_dictionary](#php_dictionary)|666|666|83|12.4%|0.8%|
[feodo](#feodo)|103|103|81|78.6%|0.7%|
[php_spammers](#php_spammers)|661|661|78|11.8%|0.7%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|59|0.8%|0.5%|
[php_commenters](#php_commenters)|403|403|59|14.6%|0.5%|
[xroxy](#xroxy)|2145|2145|36|1.6%|0.3%|
[sslbl](#sslbl)|380|380|32|8.4%|0.3%|
[openbl_60d](#openbl_60d)|7050|7050|27|0.3%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|25|0.1%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|24|0.7%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|21|0.4%|0.2%|
[proxz](#proxz)|1158|1158|20|1.7%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|19|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|15|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|13|1.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|11|2.9%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|9|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|5|0.1%|0.0%|
[proxyrss](#proxyrss)|1544|1544|5|0.3%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|5|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|3|1.6%|0.0%|
[shunlist](#shunlist)|1302|1302|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[openbl_7d](#openbl_7d)|766|766|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|1|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5150|688981125|18340608|2.6%|100.0%|
[et_block](#et_block)|999|18343755|18338560|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|108574|9626093|6933032|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3778|670299624|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|1374|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1008|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|307|1.0%|0.0%|
[firehol_level2](#firehol_level2)|26283|37939|274|0.7%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[openbl_60d](#openbl_60d)|7050|7050|236|3.3%|0.0%|
[blocklist_de](#blocklist_de)|32050|32050|206|0.6%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|121|4.2%|0.0%|
[nixspam](#nixspam)|29885|29885|121|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|118|3.7%|0.0%|
[et_compromised](#et_compromised)|1678|1678|101|6.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|101|5.8%|0.0%|
[shunlist](#shunlist)|1302|1302|97|7.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|86|1.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|57|1.7%|0.0%|
[openbl_7d](#openbl_7d)|766|766|50|6.5%|0.0%|
[php_commenters](#php_commenters)|403|403|29|7.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[openbl_1d](#openbl_1d)|144|144|23|15.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|23|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|19|0.1%|0.0%|
[zeus_badips](#zeus_badips)|202|202|16|7.9%|0.0%|
[zeus](#zeus)|232|232|16|6.8%|0.0%|
[voipbl](#voipbl)|10522|10934|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|13|0.4%|0.0%|
[php_dictionary](#php_dictionary)|666|666|6|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|6|3.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|5|0.0%|0.0%|
[php_spammers](#php_spammers)|661|661|4|0.6%|0.0%|
[malc0de](#malc0de)|338|338|4|1.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6569|6569|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11826|12064|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|76|76|2|2.6%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
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
[firehol_level1](#firehol_level1)|5150|688981125|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|999|18343755|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|108574|9626093|88|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|78|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|15|0.0%|0.0%|
[firehol_level2](#firehol_level2)|26283|37939|10|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|9|0.0%|0.0%|
[blocklist_de](#blocklist_de)|32050|32050|8|0.0%|0.0%|
[php_commenters](#php_commenters)|403|403|7|1.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|5|2.4%|0.0%|
[zeus](#zeus)|232|232|5|2.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|4|2.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|4|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|378|378|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7050|7050|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|1|0.0%|0.0%|
[malc0de](#malc0de)|338|338|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|172|172|1|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Tue Jun  9 21:15:06 UTC 2015.

The ipset `sslbl` has **380** entries, **380** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5150|688981125|380|0.0%|100.0%|
[firehol_level3](#firehol_level3)|108574|9626093|96|0.0%|25.2%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|68|0.0%|17.8%|
[shunlist](#shunlist)|1302|1302|64|4.9%|16.8%|
[feodo](#feodo)|103|103|37|35.9%|9.7%|
[et_block](#et_block)|999|18343755|37|0.0%|9.7%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|32|0.3%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|30|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11826|12064|1|0.0%|0.2%|
[firehol_level2](#firehol_level2)|26283|37939|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|32050|32050|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Tue Jun  9 21:00:01 UTC 2015.

The ipset `stopforumspam_1d` has **7240** entries, **7240** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|26283|37939|7240|19.0%|100.0%|
[firehol_level3](#firehol_level3)|108574|9626093|4837|0.0%|66.8%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|4795|5.1%|66.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|4378|14.9%|60.4%|
[blocklist_de](#blocklist_de)|32050|32050|1376|4.2%|19.0%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|1295|39.7%|17.8%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|1005|1.2%|13.8%|
[firehol_proxies](#firehol_proxies)|11826|12064|801|6.6%|11.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|523|0.0%|7.2%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|471|6.4%|6.5%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|392|3.8%|5.4%|
[et_tor](#et_tor)|6400|6400|348|5.4%|4.8%|
[dm_tor](#dm_tor)|6558|6558|346|5.2%|4.7%|
[bm_tor](#bm_tor)|6569|6569|344|5.2%|4.7%|
[proxyrss](#proxyrss)|1544|1544|311|20.1%|4.2%|
[xroxy](#xroxy)|2145|2145|250|11.6%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|212|0.0%|2.9%|
[proxz](#proxz)|1158|1158|200|17.2%|2.7%|
[php_commenters](#php_commenters)|403|403|161|39.9%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|153|41.1%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|130|0.0%|1.7%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|117|4.3%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|108|61.0%|1.4%|
[firehol_level1](#firehol_level1)|5150|688981125|89|0.0%|1.2%|
[et_block](#et_block)|999|18343755|87|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|86|0.0%|1.1%|
[nixspam](#nixspam)|29885|29885|64|0.2%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|63|0.3%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|55|0.2%|0.7%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|49|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|43|0.0%|0.5%|
[php_spammers](#php_spammers)|661|661|42|6.3%|0.5%|
[php_dictionary](#php_dictionary)|666|666|37|5.5%|0.5%|
[php_harvesters](#php_harvesters)|378|378|35|9.2%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|32|0.6%|0.4%|
[openbl_60d](#openbl_60d)|7050|7050|20|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|10|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|5|0.7%|0.0%|
[voipbl](#voipbl)|10522|10934|4|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[shunlist](#shunlist)|1302|1302|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|108574|9626093|92512|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|29167|99.6%|31.5%|
[firehol_level2](#firehol_level2)|26283|37939|6197|16.3%|6.6%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|5859|7.1%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5744|0.0%|6.2%|
[firehol_proxies](#firehol_proxies)|11826|12064|5219|43.2%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|4795|66.2%|5.1%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|3500|47.6%|3.7%|
[blocklist_de](#blocklist_de)|32050|32050|2563|7.9%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2475|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|2211|67.9%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|1511|56.7%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1506|0.0%|1.6%|
[xroxy](#xroxy)|2145|2145|1265|58.9%|1.3%|
[firehol_level1](#firehol_level1)|5150|688981125|1089|0.0%|1.1%|
[et_block](#et_block)|999|18343755|1011|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|1008|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|797|7.8%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|719|0.0%|0.7%|
[proxz](#proxz)|1158|1158|685|59.1%|0.7%|
[proxyrss](#proxyrss)|1544|1544|681|44.1%|0.7%|
[et_tor](#et_tor)|6400|6400|659|10.2%|0.7%|
[dm_tor](#dm_tor)|6558|6558|635|9.6%|0.6%|
[bm_tor](#bm_tor)|6569|6569|633|9.6%|0.6%|
[php_commenters](#php_commenters)|403|403|301|74.6%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|253|1.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|233|62.6%|0.2%|
[nixspam](#nixspam)|29885|29885|218|0.7%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|217|1.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|202|0.1%|0.2%|
[php_spammers](#php_spammers)|661|661|136|20.5%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|129|72.8%|0.1%|
[php_dictionary](#php_dictionary)|666|666|125|18.7%|0.1%|
[php_harvesters](#php_harvesters)|378|378|81|21.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|78|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|68|1.3%|0.0%|
[openbl_60d](#openbl_60d)|7050|7050|49|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|48|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|35|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|20|0.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|18|2.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|13|0.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|13|0.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|12|1.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|9|0.3%|0.0%|
[shunlist](#shunlist)|1302|1302|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[openbl_7d](#openbl_7d)|766|766|3|0.3%|0.0%|
[zeus_badips](#zeus_badips)|202|202|2|0.9%|0.0%|
[zeus](#zeus)|232|232|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[ciarmy](#ciarmy)|451|451|2|0.4%|0.0%|
[openbl_1d](#openbl_1d)|144|144|1|0.6%|0.0%|
[fullbogons](#fullbogons)|3778|670299624|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|108574|9626093|29168|0.3%|99.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|29167|31.5%|99.6%|
[firehol_level2](#firehol_level2)|26283|37939|5409|14.2%|18.4%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|4378|60.4%|14.9%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|2802|3.3%|9.5%|
[firehol_proxies](#firehol_proxies)|11826|12064|2400|19.8%|8.1%|
[blocklist_de](#blocklist_de)|32050|32050|2144|6.6%|7.3%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|1955|60.0%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1893|0.0%|6.4%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|1595|21.7%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|825|0.0%|2.8%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|652|6.4%|2.2%|
[xroxy](#xroxy)|2145|2145|648|30.2%|2.2%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|622|23.3%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|549|0.0%|1.8%|
[et_tor](#et_tor)|6400|6400|544|8.5%|1.8%|
[proxyrss](#proxyrss)|1544|1544|532|34.4%|1.8%|
[dm_tor](#dm_tor)|6558|6558|519|7.9%|1.7%|
[bm_tor](#bm_tor)|6569|6569|518|7.8%|1.7%|
[proxz](#proxz)|1158|1158|493|42.5%|1.6%|
[firehol_level1](#firehol_level1)|5150|688981125|318|0.0%|1.0%|
[et_block](#et_block)|999|18343755|308|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|307|0.0%|1.0%|
[php_commenters](#php_commenters)|403|403|227|56.3%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|192|51.6%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|157|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|138|0.7%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|134|0.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|116|65.5%|0.3%|
[nixspam](#nixspam)|29885|29885|110|0.3%|0.3%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|99|0.0%|0.3%|
[php_dictionary](#php_dictionary)|666|666|81|12.1%|0.2%|
[php_spammers](#php_spammers)|661|661|80|12.1%|0.2%|
[php_harvesters](#php_harvesters)|378|378|61|16.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|49|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7050|7050|24|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.0%|
[voipbl](#voipbl)|10522|10934|15|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|9|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|5|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|5|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|702|702|4|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|202|202|1|0.4%|0.0%|
[zeus](#zeus)|232|232|1|0.4%|0.0%|
[shunlist](#shunlist)|1302|1302|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ciarmy](#ciarmy)|451|451|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Tue Jun  9 21:32:03 UTC 2015.

The ipset `virbl` has **20** entries, **20** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|108574|9626093|20|0.0%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|10.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|5.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Tue Jun  9 17:54:16 UTC 2015.

The ipset `voipbl` has **10522** entries, **10934** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1602|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|434|0.0%|3.9%|
[firehol_level1](#firehol_level1)|5150|688981125|334|0.0%|3.0%|
[fullbogons](#fullbogons)|3778|670299624|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|299|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|191|0.1%|1.7%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|78|0.0%|0.7%|
[firehol_level3](#firehol_level3)|108574|9626093|57|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|35|0.0%|0.3%|
[firehol_level2](#firehol_level2)|26283|37939|32|0.0%|0.2%|
[blocklist_de](#blocklist_de)|32050|32050|28|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|76|76|23|30.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|15|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|14|0.0%|0.1%|
[et_block](#et_block)|999|18343755|14|0.0%|0.1%|
[shunlist](#shunlist)|1302|1302|13|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7050|7050|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2853|2853|3|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6569|6569|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16288|16288|3|0.0%|0.0%|
[nixspam](#nixspam)|29885|29885|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|2|0.1%|0.0%|
[ciarmy](#ciarmy)|451|451|2|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3111|3111|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11826|12064|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|4930|4930|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Tue Jun  9 21:33:02 UTC 2015.

The ipset `xroxy` has **2145** entries, **2145** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11826|12064|2145|17.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18450|82472|2145|2.6%|100.0%|
[firehol_level3](#firehol_level3)|108574|9626093|1279|0.0%|59.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1265|1.3%|58.9%|
[ri_web_proxies](#ri_web_proxies)|7349|7349|940|12.7%|43.8%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|648|2.2%|30.2%|
[proxz](#proxz)|1158|1158|420|36.2%|19.5%|
[proxyrss](#proxyrss)|1544|1544|387|25.0%|18.0%|
[ri_connect_proxies](#ri_connect_proxies)|2661|2661|384|14.4%|17.9%|
[firehol_level2](#firehol_level2)|26283|37939|336|0.8%|15.6%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|250|3.4%|11.6%|
[blocklist_de](#blocklist_de)|32050|32050|206|0.6%|9.6%|
[blocklist_de_bots](#blocklist_de_bots)|3256|3256|156|4.7%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|107|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.8%|
[nixspam](#nixspam)|29885|29885|65|0.2%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|50|0.2%|2.3%|
[php_dictionary](#php_dictionary)|666|666|39|5.8%|1.8%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|36|0.3%|1.6%|
[php_spammers](#php_spammers)|661|661|32|4.8%|1.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[php_commenters](#php_commenters)|403|403|8|1.9%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|5|2.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|5|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|378|378|2|0.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1721|1721|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6569|6569|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2797|2797|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  9 19:31:33 UTC 2015.

The ipset `zeus` has **232** entries, **232** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5150|688981125|232|0.0%|100.0%|
[et_block](#et_block)|999|18343755|228|0.0%|98.2%|
[firehol_level3](#firehol_level3)|108574|9626093|204|0.0%|87.9%|
[zeus_badips](#zeus_badips)|202|202|202|100.0%|87.0%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|201|1.9%|86.6%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|62|0.0%|26.7%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|16|0.0%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|7|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7050|7050|2|0.0%|0.8%|
[firehol_level2](#firehol_level2)|26283|37939|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|1|0.0%|0.4%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.4%|
[openbl_30d](#openbl_30d)|2853|2853|1|0.0%|0.4%|
[nixspam](#nixspam)|29885|29885|1|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|32050|32050|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Tue Jun  9 21:36:19 UTC 2015.

The ipset `zeus_badips` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|232|232|202|87.0%|100.0%|
[firehol_level1](#firehol_level1)|5150|688981125|202|0.0%|100.0%|
[et_block](#et_block)|999|18343755|202|0.0%|100.0%|
[firehol_level3](#firehol_level3)|108574|9626093|180|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|10136|10136|178|1.7%|88.1%|
[alienvault_reputation](#alienvault_reputation)|184826|184826|37|0.0%|18.3%|
[spamhaus_drop](#spamhaus_drop)|653|18340608|16|0.0%|7.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2|0.0%|0.9%|
[firehol_level2](#firehol_level2)|26283|37939|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7240|7240|1|0.0%|0.4%|
[php_commenters](#php_commenters)|403|403|1|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7050|7050|1|0.0%|0.4%|
[nixspam](#nixspam)|29885|29885|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|19708|19708|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|32050|32050|1|0.0%|0.4%|
