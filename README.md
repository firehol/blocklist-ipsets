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

The following list was automatically generated on Tue Jun  9 03:45:52 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|178836 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|31134 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|16150 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3494 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|5242 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|156 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2125 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|19038 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|88 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|2890 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|165 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6369 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1718 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|391 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|123 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6345 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|999 subnets, 18343755 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|509 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|1678 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6400 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|102 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|**FireHOL Anonymous** - Known anonymizing IPs. (includes: firehol_proxies anonymous bm_tor dm_tor)|ipv4 hash:net|18197 subnets, 82203 unique IPs|updated every 1 min  from [this link]()
[firehol_level1](#firehol_level1)|**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)|ipv4 hash:net|5091 subnets, 688943669 unique IPs|updated every 1 min  from [this link]()
[firehol_level2](#firehol_level2)|**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)|ipv4 hash:net|25559 subnets, 37202 unique IPs|updated every 1 min  from [this link]()
[firehol_level3](#firehol_level3)|**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)|ipv4 hash:net|107925 subnets, 9625377 unique IPs|updated every 1 min  from [this link]()
[firehol_proxies](#firehol_proxies)|**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)|ipv4 hash:net|11678 subnets, 11905 unique IPs|updated every 1 min  from [this link]()
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|29888 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|141 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|2874 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7199 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|824 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|385 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|630 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|366 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|622 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1553 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1093 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2637 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|7245 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1254 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9624 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|652 subnets, 18338560 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|380 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7442 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92512 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29277 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|14 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10507 subnets, 10919 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2138 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|233 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
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
[openbl_60d](#openbl_60d)|7199|7199|7175|99.6%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6255|0.0%|3.4%|
[et_block](#et_block)|999|18343755|5280|0.0%|2.9%|
[firehol_level3](#firehol_level3)|107925|9625377|5124|0.0%|2.8%|
[firehol_level1](#firehol_level1)|5091|688943669|5105|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4131|0.0%|2.3%|
[dshield](#dshield)|20|5120|3842|75.0%|2.1%|
[openbl_30d](#openbl_30d)|2874|2874|2856|99.3%|1.5%|
[firehol_level2](#firehol_level2)|25559|37202|1480|3.9%|0.8%|
[blocklist_de](#blocklist_de)|31134|31134|1418|4.5%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1374|0.0%|0.7%|
[shunlist](#shunlist)|1254|1254|1239|98.8%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|1187|41.0%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1094|63.6%|0.6%|
[et_compromised](#et_compromised)|1678|1678|1076|64.1%|0.6%|
[openbl_7d](#openbl_7d)|824|824|816|99.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|391|391|379|96.9%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|288|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|198|0.2%|0.1%|
[voipbl](#voipbl)|10507|10919|189|1.7%|0.1%|
[openbl_1d](#openbl_1d)|141|141|134|95.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|123|1.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|116|0.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|98|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|70|0.3%|0.0%|
[sslbl](#sslbl)|380|380|68|17.8%|0.0%|
[zeus](#zeus)|233|233|64|27.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|54|0.0%|0.0%|
[nixspam](#nixspam)|29888|29888|50|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|49|0.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|47|2.2%|0.0%|
[et_tor](#et_tor)|6400|6400|41|0.6%|0.0%|
[dm_tor](#dm_tor)|6345|6345|41|0.6%|0.0%|
[bm_tor](#bm_tor)|6369|6369|41|0.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|38|18.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|37|22.4%|0.0%|
[firehol_proxies](#firehol_proxies)|11678|11905|32|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|32|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[php_commenters](#php_commenters)|385|385|17|4.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|17|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|15|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|88|88|15|17.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|14|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|11|3.0%|0.0%|
[malc0de](#malc0de)|342|342|10|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|10|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|9|5.7%|0.0%|
[php_dictionary](#php_dictionary)|630|630|8|1.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|7|0.5%|0.0%|
[php_spammers](#php_spammers)|622|622|5|0.8%|0.0%|
[et_botcc](#et_botcc)|509|509|5|0.9%|0.0%|
[xroxy](#xroxy)|2138|2138|4|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|3|0.1%|0.0%|
[proxz](#proxz)|1093|1093|3|0.2%|0.0%|
[feodo](#feodo)|102|102|2|1.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|2|1.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Tue Jun  9 03:14:03 UTC 2015.

The ipset `blocklist_de` has **31134** entries, **31134** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25559|37202|31134|83.6%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|19038|100.0%|61.1%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|16148|99.9%|51.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|5242|100.0%|16.8%|
[firehol_level3](#firehol_level3)|107925|9625377|4116|0.0%|13.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3644|0.0%|11.7%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|3488|99.8%|11.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|2890|100.0%|9.2%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2698|2.9%|8.6%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2327|7.9%|7.4%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|2119|99.7%|6.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1607|0.0%|5.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1562|0.0%|5.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|1418|0.7%|4.5%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|1401|18.8%|4.4%|
[openbl_60d](#openbl_60d)|7199|7199|1081|15.0%|3.4%|
[openbl_30d](#openbl_30d)|2874|2874|853|29.6%|2.7%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|728|42.3%|2.3%|
[nixspam](#nixspam)|29888|29888|710|2.3%|2.2%|
[et_compromised](#et_compromised)|1678|1678|657|39.1%|2.1%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|615|0.7%|1.9%|
[firehol_proxies](#firehol_proxies)|11678|11905|610|5.1%|1.9%|
[shunlist](#shunlist)|1254|1254|444|35.4%|1.4%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|417|5.7%|1.3%|
[openbl_7d](#openbl_7d)|824|824|400|48.5%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|300|3.1%|0.9%|
[firehol_level1](#firehol_level1)|5091|688943669|221|0.0%|0.7%|
[proxyrss](#proxyrss)|1553|1553|210|13.5%|0.6%|
[xroxy](#xroxy)|2138|2138|207|9.6%|0.6%|
[et_block](#et_block)|999|18343755|201|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|189|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|165|100.0%|0.5%|
[proxz](#proxz)|1093|1093|159|14.5%|0.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|152|97.4%|0.4%|
[openbl_1d](#openbl_1d)|141|141|114|80.8%|0.3%|
[php_commenters](#php_commenters)|385|385|93|24.1%|0.2%|
[dshield](#dshield)|20|5120|93|1.8%|0.2%|
[php_dictionary](#php_dictionary)|630|630|90|14.2%|0.2%|
[php_spammers](#php_spammers)|622|622|83|13.3%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|79|2.9%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|88|88|69|78.4%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|47|0.0%|0.1%|
[php_harvesters](#php_harvesters)|366|366|42|11.4%|0.1%|
[ciarmy](#ciarmy)|391|391|36|9.2%|0.1%|
[voipbl](#voipbl)|10507|10919|30|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|10|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|8|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6345|6345|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6369|6369|4|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Tue Jun  9 03:28:06 UTC 2015.

The ipset `blocklist_de_apache` has **16150** entries, **16150** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25559|37202|16148|43.4%|99.9%|
[blocklist_de](#blocklist_de)|31134|31134|16148|51.8%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|11059|58.0%|68.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|4828|92.1%|29.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2430|0.0%|15.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1331|0.0%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1099|0.0%|6.8%|
[firehol_level3](#firehol_level3)|107925|9625377|282|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|210|0.2%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|129|0.4%|0.7%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|116|0.0%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|63|0.8%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|34|20.6%|0.2%|
[ciarmy](#ciarmy)|391|391|31|7.9%|0.1%|
[shunlist](#shunlist)|1254|1254|30|2.3%|0.1%|
[php_commenters](#php_commenters)|385|385|30|7.7%|0.1%|
[nixspam](#nixspam)|29888|29888|30|0.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|21|0.6%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|13|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|11|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11678|11905|9|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5091|688943669|8|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|7|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|7|1.1%|0.0%|
[et_tor](#et_tor)|6400|6400|7|0.1%|0.0%|
[et_block](#et_block)|999|18343755|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|5|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6345|6345|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6369|6369|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[openbl_60d](#openbl_60d)|7199|7199|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2874|2874|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1553|1553|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Tue Jun  9 03:28:08 UTC 2015.

The ipset `blocklist_de_bots` has **3494** entries, **3494** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25559|37202|3489|9.3%|99.8%|
[blocklist_de](#blocklist_de)|31134|31134|3488|11.2%|99.8%|
[firehol_level3](#firehol_level3)|107925|9625377|2393|0.0%|68.4%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2370|2.5%|67.8%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2144|7.3%|61.3%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|1330|17.8%|38.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|521|0.6%|14.9%|
[firehol_proxies](#firehol_proxies)|11678|11905|519|4.3%|14.8%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|355|4.8%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|233|0.0%|6.6%|
[proxyrss](#proxyrss)|1553|1553|208|13.3%|5.9%|
[xroxy](#xroxy)|2138|2138|167|7.8%|4.7%|
[proxz](#proxz)|1093|1093|139|12.7%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|125|0.0%|3.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|121|73.3%|3.4%|
[php_commenters](#php_commenters)|385|385|76|19.7%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|75|2.8%|2.1%|
[nixspam](#nixspam)|29888|29888|49|0.1%|1.4%|
[firehol_level1](#firehol_level1)|5091|688943669|49|0.0%|1.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|46|0.0%|1.3%|
[et_block](#et_block)|999|18343755|46|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|37|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|32|0.0%|0.9%|
[php_harvesters](#php_harvesters)|366|366|31|8.4%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|29|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|28|0.2%|0.8%|
[php_dictionary](#php_dictionary)|630|630|24|3.8%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|21|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|21|0.1%|0.6%|
[php_spammers](#php_spammers)|622|622|18|2.8%|0.5%|
[openbl_60d](#openbl_60d)|7199|7199|16|0.2%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|3|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6345|6345|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6369|6369|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Tue Jun  9 03:14:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **5242** entries, **5242** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25559|37202|5242|14.0%|100.0%|
[blocklist_de](#blocklist_de)|31134|31134|5242|16.8%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|4828|29.8%|92.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|379|0.0%|7.2%|
[firehol_level3](#firehol_level3)|107925|9625377|81|0.0%|1.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|65|0.0%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|64|0.0%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|44|0.1%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|44|0.0%|0.8%|
[nixspam](#nixspam)|29888|29888|32|0.1%|0.6%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|27|0.3%|0.5%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|17|0.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|10|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|9|0.0%|0.1%|
[php_commenters](#php_commenters)|385|385|9|2.3%|0.1%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|8|0.1%|0.1%|
[firehol_proxies](#firehol_proxies)|11678|11905|8|0.0%|0.1%|
[php_spammers](#php_spammers)|622|622|7|1.1%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|7|4.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|6|0.0%|0.1%|
[php_dictionary](#php_dictionary)|630|630|5|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5091|688943669|4|0.0%|0.0%|
[et_block](#et_block)|999|18343755|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6345|6345|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6369|6369|2|0.0%|0.0%|
[xroxy](#xroxy)|2138|2138|1|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.0%|
[shunlist](#shunlist)|1254|1254|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|1|0.0%|0.0%|
[proxz](#proxz)|1093|1093|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[ciarmy](#ciarmy)|391|391|1|0.2%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Tue Jun  9 03:28:06 UTC 2015.

The ipset `blocklist_de_ftp` has **156** entries, **156** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25559|37202|152|0.4%|97.4%|
[blocklist_de](#blocklist_de)|31134|31134|152|0.4%|97.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|17|0.0%|10.8%|
[firehol_level3](#firehol_level3)|107925|9625377|16|0.0%|10.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|10|0.0%|6.4%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|9|0.0%|5.7%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|6|0.0%|3.8%|
[php_harvesters](#php_harvesters)|366|366|6|1.6%|3.8%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2|0.0%|1.2%|
[openbl_60d](#openbl_60d)|7199|7199|2|0.0%|1.2%|
[openbl_30d](#openbl_30d)|2874|2874|2|0.0%|1.2%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|1|0.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|1|0.0%|0.6%|
[shunlist](#shunlist)|1254|1254|1|0.0%|0.6%|
[openbl_7d](#openbl_7d)|824|824|1|0.1%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|0.6%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|1|0.0%|0.6%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.6%|
[ciarmy](#ciarmy)|391|391|1|0.2%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.6%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Tue Jun  9 03:28:06 UTC 2015.

The ipset `blocklist_de_imap` has **2125** entries, **2125** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25559|37202|2119|5.6%|99.7%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|2119|11.1%|99.7%|
[blocklist_de](#blocklist_de)|31134|31134|2119|6.8%|99.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|195|0.0%|9.1%|
[firehol_level3](#firehol_level3)|107925|9625377|61|0.0%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|50|0.0%|2.3%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|47|0.0%|2.2%|
[openbl_60d](#openbl_60d)|7199|7199|37|0.5%|1.7%|
[openbl_30d](#openbl_30d)|2874|2874|32|1.1%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|23|0.0%|1.0%|
[nixspam](#nixspam)|29888|29888|22|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|15|0.1%|0.7%|
[firehol_level1](#firehol_level1)|5091|688943669|15|0.0%|0.7%|
[et_block](#et_block)|999|18343755|15|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|14|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|11|0.0%|0.5%|
[openbl_7d](#openbl_7d)|824|824|11|1.3%|0.5%|
[et_compromised](#et_compromised)|1678|1678|7|0.4%|0.3%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|7|0.4%|0.3%|
[firehol_proxies](#firehol_proxies)|11678|11905|5|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|5|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|4|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|3|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.1%|
[shunlist](#shunlist)|1254|1254|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|630|630|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|141|141|1|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[ciarmy](#ciarmy)|391|391|1|0.2%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Tue Jun  9 03:14:05 UTC 2015.

The ipset `blocklist_de_mail` has **19038** entries, **19038** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25559|37202|19038|51.1%|100.0%|
[blocklist_de](#blocklist_de)|31134|31134|19038|61.1%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|11059|68.4%|58.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2617|0.0%|13.7%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|2119|99.7%|11.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1407|0.0%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1251|0.0%|6.5%|
[nixspam](#nixspam)|29888|29888|627|2.0%|3.2%|
[firehol_level3](#firehol_level3)|107925|9625377|498|0.0%|2.6%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|260|2.7%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|238|0.2%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|132|0.4%|0.6%|
[firehol_proxies](#firehol_proxies)|11678|11905|80|0.6%|0.4%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|80|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|70|0.0%|0.3%|
[php_dictionary](#php_dictionary)|630|630|61|9.6%|0.3%|
[php_spammers](#php_spammers)|622|622|57|9.1%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|55|0.7%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|52|0.7%|0.2%|
[openbl_60d](#openbl_60d)|7199|7199|49|0.6%|0.2%|
[openbl_30d](#openbl_30d)|2874|2874|41|1.4%|0.2%|
[xroxy](#xroxy)|2138|2138|39|1.8%|0.2%|
[firehol_level1](#firehol_level1)|5091|688943669|25|0.0%|0.1%|
[php_commenters](#php_commenters)|385|385|24|6.2%|0.1%|
[et_block](#et_block)|999|18343755|23|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|23|13.9%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|22|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|21|0.6%|0.1%|
[proxz](#proxz)|1093|1093|18|1.6%|0.0%|
[openbl_7d](#openbl_7d)|824|824|12|1.4%|0.0%|
[et_compromised](#et_compromised)|1678|1678|12|0.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|11|0.6%|0.0%|
[shunlist](#shunlist)|1254|1254|4|0.3%|0.0%|
[php_harvesters](#php_harvesters)|366|366|4|1.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[openbl_1d](#openbl_1d)|141|141|2|1.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1553|1553|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6345|6345|1|0.0%|0.0%|
[ciarmy](#ciarmy)|391|391|1|0.2%|0.0%|
[bm_tor](#bm_tor)|6369|6369|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Tue Jun  9 03:14:08 UTC 2015.

The ipset `blocklist_de_sip` has **88** entries, **88** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25559|37202|69|0.1%|78.4%|
[blocklist_de](#blocklist_de)|31134|31134|69|0.2%|78.4%|
[voipbl](#voipbl)|10507|10919|25|0.2%|28.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|18.1%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|15|0.0%|17.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|9.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|6.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.2%|
[firehol_level3](#firehol_level3)|107925|9625377|2|0.0%|2.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|1.1%|
[firehol_level1](#firehol_level1)|5091|688943669|1|0.0%|1.1%|
[et_botcc](#et_botcc)|509|509|1|0.1%|1.1%|
[et_block](#et_block)|999|18343755|1|0.0%|1.1%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Tue Jun  9 03:14:04 UTC 2015.

The ipset `blocklist_de_ssh` has **2890** entries, **2890** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25559|37202|2890|7.7%|100.0%|
[blocklist_de](#blocklist_de)|31134|31134|2890|9.2%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|1187|0.6%|41.0%|
[firehol_level3](#firehol_level3)|107925|9625377|1069|0.0%|36.9%|
[openbl_60d](#openbl_60d)|7199|7199|1012|14.0%|35.0%|
[openbl_30d](#openbl_30d)|2874|2874|808|28.1%|27.9%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|716|41.6%|24.7%|
[et_compromised](#et_compromised)|1678|1678|644|38.3%|22.2%|
[shunlist](#shunlist)|1254|1254|409|32.6%|14.1%|
[openbl_7d](#openbl_7d)|824|824|387|46.9%|13.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|361|0.0%|12.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|139|0.0%|4.8%|
[firehol_level1](#firehol_level1)|5091|688943669|138|0.0%|4.7%|
[et_block](#et_block)|999|18343755|125|0.0%|4.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|116|0.0%|4.0%|
[openbl_1d](#openbl_1d)|141|141|112|79.4%|3.8%|
[dshield](#dshield)|20|5120|89|1.7%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|67|0.0%|2.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|29|17.5%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|15|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|3|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|2|0.0%|0.0%|
[nixspam](#nixspam)|29888|29888|2|0.0%|0.0%|
[ciarmy](#ciarmy)|391|391|2|0.5%|0.0%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Tue Jun  9 03:28:09 UTC 2015.

The ipset `blocklist_de_strongips` has **165** entries, **165** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25559|37202|165|0.4%|100.0%|
[blocklist_de](#blocklist_de)|31134|31134|165|0.5%|100.0%|
[firehol_level3](#firehol_level3)|107925|9625377|153|0.0%|92.7%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|124|0.1%|75.1%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|121|3.4%|73.3%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|114|0.3%|69.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|104|1.3%|63.0%|
[php_commenters](#php_commenters)|385|385|42|10.9%|25.4%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|37|0.0%|22.4%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|34|0.2%|20.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|29|1.0%|17.5%|
[openbl_60d](#openbl_60d)|7199|7199|26|0.3%|15.7%|
[openbl_30d](#openbl_30d)|2874|2874|25|0.8%|15.1%|
[openbl_7d](#openbl_7d)|824|824|24|2.9%|14.5%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|23|0.1%|13.9%|
[shunlist](#shunlist)|1254|1254|22|1.7%|13.3%|
[openbl_1d](#openbl_1d)|141|141|17|12.0%|10.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|16|0.0%|9.6%|
[firehol_level1](#firehol_level1)|5091|688943669|14|0.0%|8.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|7|0.1%|4.2%|
[php_spammers](#php_spammers)|622|622|6|0.9%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|3.6%|
[dshield](#dshield)|20|5120|6|0.1%|3.6%|
[xroxy](#xroxy)|2138|2138|5|0.2%|3.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|3.0%|
[firehol_proxies](#firehol_proxies)|11678|11905|5|0.0%|3.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|5|0.0%|3.0%|
[et_block](#et_block)|999|18343755|5|0.0%|3.0%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|4|0.0%|2.4%|
[proxyrss](#proxyrss)|1553|1553|4|0.2%|2.4%|
[php_dictionary](#php_dictionary)|630|630|4|0.6%|2.4%|
[nixspam](#nixspam)|29888|29888|4|0.0%|2.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|1.8%|
[proxz](#proxz)|1093|1093|3|0.2%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|2|0.0%|1.2%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|1.2%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.6%|
[ciarmy](#ciarmy)|391|391|1|0.2%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.6%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Tue Jun  9 03:18:03 UTC 2015.

The ipset `bm_tor` has **6369** entries, **6369** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18197|82203|6369|7.7%|100.0%|
[dm_tor](#dm_tor)|6345|6345|6152|96.9%|96.5%|
[et_tor](#et_tor)|6400|6400|5902|92.2%|92.6%|
[firehol_level3](#firehol_level3)|107925|9625377|1067|0.0%|16.7%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|1029|10.6%|16.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|635|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|619|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|520|1.7%|8.1%|
[firehol_level2](#firehol_level2)|25559|37202|352|0.9%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|351|4.7%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|182|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11678|11905|166|1.3%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|164|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|163|43.8%|2.5%|
[php_commenters](#php_commenters)|385|385|43|11.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|41|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7199|7199|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|366|366|7|1.9%|0.1%|
[nixspam](#nixspam)|29888|29888|5|0.0%|0.0%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31134|31134|4|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|3|0.4%|0.0%|
[firehol_level1](#firehol_level1)|5091|688943669|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|2|0.0%|0.0%|
[xroxy](#xroxy)|2138|2138|1|0.0%|0.0%|
[shunlist](#shunlist)|1254|1254|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5091|688943669|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10507|10919|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|107925|9625377|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|391|391|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Tue Jun  9 02:36:26 UTC 2015.

The ipset `bruteforceblocker` has **1718** entries, **1718** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107925|9625377|1718|0.0%|100.0%|
[et_compromised](#et_compromised)|1678|1678|1634|97.3%|95.1%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|1094|0.6%|63.6%|
[openbl_60d](#openbl_60d)|7199|7199|994|13.8%|57.8%|
[openbl_30d](#openbl_30d)|2874|2874|933|32.4%|54.3%|
[firehol_level2](#firehol_level2)|25559|37202|734|1.9%|42.7%|
[blocklist_de](#blocklist_de)|31134|31134|728|2.3%|42.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|716|24.7%|41.6%|
[shunlist](#shunlist)|1254|1254|432|34.4%|25.1%|
[openbl_7d](#openbl_7d)|824|824|317|38.4%|18.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|153|0.0%|8.9%|
[firehol_level1](#firehol_level1)|5091|688943669|108|0.0%|6.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|101|0.0%|5.8%|
[et_block](#et_block)|999|18343755|101|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|90|0.0%|5.2%|
[dshield](#dshield)|20|5120|65|1.2%|3.7%|
[openbl_1d](#openbl_1d)|141|141|63|44.6%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|51|0.0%|2.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|13|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|11|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|7|0.3%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11678|11905|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|3|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|2|0.0%|0.1%|
[proxz](#proxz)|1093|1093|2|0.1%|0.1%|
[nixspam](#nixspam)|29888|29888|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[xroxy](#xroxy)|2138|2138|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1553|1553|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.0%|
[ciarmy](#ciarmy)|391|391|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|1|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|1|0.6%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Tue Jun  9 01:15:18 UTC 2015.

The ipset `ciarmy` has **391** entries, **391** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107925|9625377|391|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|379|0.2%|96.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|79|0.0%|20.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|44|0.0%|11.2%|
[firehol_level2](#firehol_level2)|25559|37202|37|0.0%|9.4%|
[blocklist_de](#blocklist_de)|31134|31134|36|0.1%|9.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|34|0.0%|8.6%|
[shunlist](#shunlist)|1254|1254|31|2.4%|7.9%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|31|0.1%|7.9%|
[firehol_level1](#firehol_level1)|5091|688943669|4|0.0%|1.0%|
[et_block](#et_block)|999|18343755|4|0.0%|1.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|2|0.0%|0.5%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|824|824|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7199|7199|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|2874|2874|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|141|141|1|0.7%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|1|0.6%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|1|0.6%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|1|0.0%|0.2%|

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
[firehol_level3](#firehol_level3)|107925|9625377|123|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|12|0.0%|9.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|8.1%|
[malc0de](#malc0de)|342|342|8|2.3%|6.5%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|4|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|1.6%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|2|0.0%|1.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.8%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5091|688943669|1|0.0%|0.8%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Tue Jun  9 03:36:06 UTC 2015.

The ipset `dm_tor` has **6345** entries, **6345** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18197|82203|6345|7.7%|100.0%|
[bm_tor](#bm_tor)|6369|6369|6152|96.5%|96.9%|
[et_tor](#et_tor)|6400|6400|5778|90.2%|91.0%|
[firehol_level3](#firehol_level3)|107925|9625377|1059|0.0%|16.6%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|1021|10.6%|16.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|634|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|614|0.0%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|520|1.7%|8.1%|
[firehol_level2](#firehol_level2)|25559|37202|353|0.9%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|352|4.7%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|183|0.0%|2.8%|
[firehol_proxies](#firehol_proxies)|11678|11905|166|1.3%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|163|43.8%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|163|0.0%|2.5%|
[php_commenters](#php_commenters)|385|385|43|11.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|41|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7199|7199|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|366|366|7|1.9%|0.1%|
[nixspam](#nixspam)|29888|29888|5|0.0%|0.0%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31134|31134|4|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|3|0.4%|0.0%|
[firehol_level1](#firehol_level1)|5091|688943669|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|2|0.0%|0.0%|
[xroxy](#xroxy)|2138|2138|1|0.0%|0.0%|
[shunlist](#shunlist)|1254|1254|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Mon Jun  8 23:55:55 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5091|688943669|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|3842|2.1%|75.0%|
[et_block](#et_block)|999|18343755|2048|0.0%|40.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|768|0.0%|15.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|256|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|256|0.0%|5.0%|
[firehol_level3](#firehol_level3)|107925|9625377|131|0.0%|2.5%|
[openbl_60d](#openbl_60d)|7199|7199|130|1.8%|2.5%|
[openbl_30d](#openbl_30d)|2874|2874|112|3.8%|2.1%|
[shunlist](#shunlist)|1254|1254|104|8.2%|2.0%|
[firehol_level2](#firehol_level2)|25559|37202|93|0.2%|1.8%|
[blocklist_de](#blocklist_de)|31134|31134|93|0.2%|1.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|89|3.0%|1.7%|
[et_compromised](#et_compromised)|1678|1678|65|3.8%|1.2%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|65|3.7%|1.2%|
[openbl_7d](#openbl_7d)|824|824|18|2.1%|0.3%|
[openbl_1d](#openbl_1d)|141|141|11|7.8%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|6|3.6%|0.1%|
[ciarmy](#ciarmy)|391|391|3|0.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|3|0.0%|0.0%|
[malc0de](#malc0de)|342|342|2|0.5%|0.0%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5091|688943669|18340676|2.6%|99.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|18338560|100.0%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8533288|2.4%|46.5%|
[firehol_level3](#firehol_level3)|107925|9625377|6933331|72.0%|37.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272541|0.2%|12.3%|
[fullbogons](#fullbogons)|3720|670264216|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130394|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|5280|2.9%|0.0%|
[dshield](#dshield)|20|5120|2048|40.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1041|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1011|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|308|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|301|3.1%|0.0%|
[firehol_level2](#firehol_level2)|25559|37202|263|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7199|7199|250|3.4%|0.0%|
[zeus](#zeus)|233|233|229|98.2%|0.0%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|0.0%|
[blocklist_de](#blocklist_de)|31134|31134|201|0.6%|0.0%|
[nixspam](#nixspam)|29888|29888|143|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2874|2874|127|4.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|125|4.3%|0.0%|
[shunlist](#shunlist)|1254|1254|103|8.2%|0.0%|
[et_compromised](#et_compromised)|1678|1678|101|6.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|101|5.8%|0.0%|
[feodo](#feodo)|102|102|99|97.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|79|1.0%|0.0%|
[openbl_7d](#openbl_7d)|824|824|46|5.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|46|1.3%|0.0%|
[sslbl](#sslbl)|380|380|37|9.7%|0.0%|
[php_commenters](#php_commenters)|385|385|30|7.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|23|0.1%|0.0%|
[openbl_1d](#openbl_1d)|141|141|18|12.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|15|0.7%|0.0%|
[voipbl](#voipbl)|10507|10919|14|0.1%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|9|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|8|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|6|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|6|0.0%|0.0%|
[malc0de](#malc0de)|342|342|5|1.4%|0.0%|
[et_tor](#et_tor)|6400|6400|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6345|6345|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6369|6369|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|5|3.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[ciarmy](#ciarmy)|391|391|4|1.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|4|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11678|11905|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|88|88|1|1.1%|0.0%|

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
[firehol_level3](#firehol_level3)|107925|9625377|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5091|688943669|1|0.0%|0.1%|
[et_block](#et_block)|999|18343755|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|88|88|1|1.1%|0.1%|

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
[firehol_level3](#firehol_level3)|107925|9625377|1650|0.0%|98.3%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1634|95.1%|97.3%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|1076|0.6%|64.1%|
[openbl_60d](#openbl_60d)|7199|7199|980|13.6%|58.4%|
[openbl_30d](#openbl_30d)|2874|2874|918|31.9%|54.7%|
[firehol_level2](#firehol_level2)|25559|37202|663|1.7%|39.5%|
[blocklist_de](#blocklist_de)|31134|31134|657|2.1%|39.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|644|22.2%|38.3%|
[shunlist](#shunlist)|1254|1254|413|32.9%|24.6%|
[openbl_7d](#openbl_7d)|824|824|307|37.2%|18.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|151|0.0%|8.9%|
[firehol_level1](#firehol_level1)|5091|688943669|107|0.0%|6.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|101|0.0%|6.0%|
[et_block](#et_block)|999|18343755|101|0.0%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|86|0.0%|5.1%|
[dshield](#dshield)|20|5120|65|1.2%|3.8%|
[openbl_1d](#openbl_1d)|141|141|54|38.2%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|46|0.0%|2.7%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|13|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|12|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|7|0.3%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|11678|11905|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|3|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|2|0.0%|0.1%|
[proxz](#proxz)|1093|1093|2|0.1%|0.1%|
[nixspam](#nixspam)|29888|29888|2|0.0%|0.1%|
[xroxy](#xroxy)|2138|2138|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1553|1553|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[ciarmy](#ciarmy)|391|391|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|1|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|1|0.6%|0.0%|

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
[firehol_anonymous](#firehol_anonymous)|18197|82203|5930|7.2%|92.6%|
[bm_tor](#bm_tor)|6369|6369|5902|92.6%|92.2%|
[dm_tor](#dm_tor)|6345|6345|5778|91.0%|90.2%|
[firehol_level3](#firehol_level3)|107925|9625377|1121|0.0%|17.5%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|1083|11.2%|16.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|659|0.7%|10.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|623|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|544|1.8%|8.5%|
[firehol_level2](#firehol_level2)|25559|37202|361|0.9%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|356|4.7%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|186|0.0%|2.9%|
[firehol_proxies](#firehol_proxies)|11678|11905|168|1.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|166|0.0%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|165|44.3%|2.5%|
[php_commenters](#php_commenters)|385|385|43|11.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|41|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7199|7199|20|0.2%|0.3%|
[blocklist_de](#blocklist_de)|31134|31134|8|0.0%|0.1%|
[php_harvesters](#php_harvesters)|366|366|7|1.9%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|7|0.0%|0.1%|
[et_block](#et_block)|999|18343755|5|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[nixspam](#nixspam)|29888|29888|4|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|4|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|3|0.4%|0.0%|
[firehol_level1](#firehol_level1)|5091|688943669|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|3|0.0%|0.0%|
[xroxy](#xroxy)|2138|2138|1|0.0%|0.0%|
[shunlist](#shunlist)|1254|1254|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  9 03:18:23 UTC 2015.

The ipset `feodo` has **102** entries, **102** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5091|688943669|102|0.0%|100.0%|
[et_block](#et_block)|999|18343755|99|0.0%|97.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|79|0.8%|77.4%|
[firehol_level3](#firehol_level3)|107925|9625377|79|0.0%|77.4%|
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

The ipset `firehol_anonymous` has **18197** entries, **82203** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11678|11905|11905|100.0%|14.4%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|7245|100.0%|8.8%|
[firehol_level3](#firehol_level3)|107925|9625377|6397|0.0%|7.7%|
[bm_tor](#bm_tor)|6369|6369|6369|100.0%|7.7%|
[dm_tor](#dm_tor)|6345|6345|6345|100.0%|7.7%|
[et_tor](#et_tor)|6400|6400|5930|92.6%|7.2%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|5899|6.3%|7.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3416|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2879|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2831|0.0%|3.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2829|9.6%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|2637|100.0%|3.2%|
[xroxy](#xroxy)|2138|2138|2138|100.0%|2.6%|
[proxyrss](#proxyrss)|1553|1553|1553|100.0%|1.8%|
[firehol_level2](#firehol_level2)|25559|37202|1405|3.7%|1.7%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|1133|11.7%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|1102|14.8%|1.3%|
[proxz](#proxz)|1093|1093|1093|100.0%|1.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.8%|
[blocklist_de](#blocklist_de)|31134|31134|615|1.9%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|521|14.9%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|0.4%|
[nixspam](#nixspam)|29888|29888|132|0.4%|0.1%|
[php_dictionary](#php_dictionary)|630|630|82|13.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|80|0.4%|0.0%|
[voipbl](#voipbl)|10507|10919|78|0.7%|0.0%|
[php_commenters](#php_commenters)|385|385|71|18.4%|0.0%|
[php_spammers](#php_spammers)|622|622|69|11.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|54|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|28|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7199|7199|23|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|11|3.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|11|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|10|0.1%|0.0%|
[et_block](#et_block)|999|18343755|8|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5091|688943669|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|5|3.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|5|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|1678|1678|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|3|0.1%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[shunlist](#shunlist)|1254|1254|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2874|2874|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|1|0.6%|0.0%|

## firehol_level1

**FireHOL Level 1** - Maximum protection without false positives. (includes: fullbogons dshield feodo palevo sslbl zeus spamhaus_drop spamhaus_edrop)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5091** entries, **688943669** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3720|670264216|670264216|100.0%|97.2%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[et_block](#et_block)|999|18343755|18340676|99.9%|2.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|18338560|100.0%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8864898|2.5%|1.2%|
[firehol_level3](#firehol_level3)|107925|9625377|7499694|77.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7497728|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4637028|3.3%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2545681|0.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|0.0%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|5105|2.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1931|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1088|1.1%|0.0%|
[sslbl](#sslbl)|380|380|380|100.0%|0.0%|
[voipbl](#voipbl)|10507|10919|334|3.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|316|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7199|7199|304|4.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|299|3.1%|0.0%|
[firehol_level2](#firehol_level2)|25559|37202|283|0.7%|0.0%|
[zeus](#zeus)|233|233|233|100.0%|0.0%|
[blocklist_de](#blocklist_de)|31134|31134|221|0.7%|0.0%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|0.0%|
[shunlist](#shunlist)|1254|1254|192|15.3%|0.0%|
[openbl_30d](#openbl_30d)|2874|2874|166|5.7%|0.0%|
[nixspam](#nixspam)|29888|29888|147|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|138|4.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|108|6.2%|0.0%|
[et_compromised](#et_compromised)|1678|1678|107|6.3%|0.0%|
[feodo](#feodo)|102|102|102|100.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|79|1.0%|0.0%|
[openbl_7d](#openbl_7d)|824|824|53|6.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|49|1.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|38|2.9%|0.0%|
[php_commenters](#php_commenters)|385|385|37|9.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|25|0.1%|0.0%|
[openbl_1d](#openbl_1d)|141|141|21|14.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|15|0.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|14|8.4%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|8|0.0%|0.0%|
[malc0de](#malc0de)|342|342|7|2.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|7|0.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|6|0.9%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[ciarmy](#ciarmy)|391|391|4|1.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|3|0.8%|0.0%|
[firehol_proxies](#firehol_proxies)|11678|11905|3|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6345|6345|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6369|6369|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[virbl](#virbl)|14|14|1|7.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|1|0.8%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|88|88|1|1.1%|0.0%|

## firehol_level2

**FireHOL Level 2** - Maximum protection from attacks took place in the last 48 hours. (includes: openbl_1d blocklist_de stopforumspam_1d)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **25559** entries, **37202** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|31134|31134|31134|100.0%|83.6%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|19038|100.0%|51.1%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|16148|99.9%|43.4%|
[firehol_level3](#firehol_level3)|107925|9625377|9866|0.1%|26.5%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|8414|9.0%|22.6%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|8086|27.6%|21.7%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|7442|100.0%|20.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|5242|100.0%|14.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4111|0.0%|11.0%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|3489|99.8%|9.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|2890|100.0%|7.7%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|2119|99.7%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1772|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1682|0.0%|4.5%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|1480|0.8%|3.9%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|1405|1.7%|3.7%|
[firehol_proxies](#firehol_proxies)|11678|11905|1193|10.0%|3.2%|
[openbl_60d](#openbl_60d)|7199|7199|1129|15.6%|3.0%|
[openbl_30d](#openbl_30d)|2874|2874|881|30.6%|2.3%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|734|42.7%|1.9%|
[nixspam](#nixspam)|29888|29888|731|2.4%|1.9%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|708|9.7%|1.9%|
[et_compromised](#et_compromised)|1678|1678|663|39.5%|1.7%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|661|6.8%|1.7%|
[shunlist](#shunlist)|1254|1254|450|35.8%|1.2%|
[openbl_7d](#openbl_7d)|824|824|426|51.6%|1.1%|
[proxyrss](#proxyrss)|1553|1553|414|26.6%|1.1%|
[xroxy](#xroxy)|2138|2138|368|17.2%|0.9%|
[et_tor](#et_tor)|6400|6400|361|5.6%|0.9%|
[dm_tor](#dm_tor)|6345|6345|353|5.5%|0.9%|
[bm_tor](#bm_tor)|6369|6369|352|5.5%|0.9%|
[firehol_level1](#firehol_level1)|5091|688943669|283|0.0%|0.7%|
[et_block](#et_block)|999|18343755|263|0.0%|0.7%|
[proxz](#proxz)|1093|1093|253|23.1%|0.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|250|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|190|7.2%|0.5%|
[php_commenters](#php_commenters)|385|385|180|46.7%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|165|100.0%|0.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|157|42.2%|0.4%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|152|97.4%|0.4%|
[openbl_1d](#openbl_1d)|141|141|141|100.0%|0.3%|
[php_spammers](#php_spammers)|622|622|97|15.5%|0.2%|
[php_dictionary](#php_dictionary)|630|630|96|15.2%|0.2%|
[dshield](#dshield)|20|5120|93|1.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|70|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|88|88|69|78.4%|0.1%|
[php_harvesters](#php_harvesters)|366|366|57|15.5%|0.1%|
[ciarmy](#ciarmy)|391|391|37|9.4%|0.0%|
[voipbl](#voipbl)|10507|10919|35|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|14|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|10|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|8|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[zeus_badips](#zeus_badips)|203|203|2|0.9%|0.0%|
[zeus](#zeus)|233|233|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|

## firehol_level3

**FireHOL Level 3** - All the bad IPs in last 30 days. (includes: openbl_30d stopforumspam_30d virbl malc0de shunlist malwaredomainlist bruteforceblocker ciarmy cleanmx_viruses snort_ipfilter ib_bluetack_spyware ib_bluetack_hijacked ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **107925** entries, **9625377** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9177856|100.0%|95.3%|
[firehol_level1](#firehol_level1)|5091|688943669|7499694|1.0%|77.9%|
[et_block](#et_block)|999|18343755|6933331|37.7%|72.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6933030|37.8%|72.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2537295|0.7%|26.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|919946|0.1%|9.5%|
[fullbogons](#fullbogons)|3720|670264216|566181|0.0%|5.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|161468|0.1%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|92512|100.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|29168|99.6%|0.3%|
[firehol_level2](#firehol_level2)|25559|37202|9866|26.5%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|9624|100.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|7083|95.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|6397|7.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11678|11905|5319|44.6%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|5124|2.8%|0.0%|
[blocklist_de](#blocklist_de)|31134|31134|4116|13.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|3508|48.4%|0.0%|
[openbl_60d](#openbl_60d)|7199|7199|3006|41.7%|0.0%|
[openbl_30d](#openbl_30d)|2874|2874|2874|100.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|2393|68.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1718|100.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1650|98.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|1499|56.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.0%|
[xroxy](#xroxy)|2138|2138|1279|59.8%|0.0%|
[shunlist](#shunlist)|1254|1254|1254|100.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1121|17.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|1069|36.9%|0.0%|
[bm_tor](#bm_tor)|6369|6369|1067|16.7%|0.0%|
[dm_tor](#dm_tor)|6345|6345|1059|16.6%|0.0%|
[openbl_7d](#openbl_7d)|824|824|824|100.0%|0.0%|
[proxyrss](#proxyrss)|1553|1553|778|50.0%|0.0%|
[nixspam](#nixspam)|29888|29888|667|2.2%|0.0%|
[proxz](#proxz)|1093|1093|663|60.6%|0.0%|
[php_dictionary](#php_dictionary)|630|630|630|100.0%|0.0%|
[php_spammers](#php_spammers)|622|622|622|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|498|2.6%|0.0%|
[ciarmy](#ciarmy)|391|391|391|100.0%|0.0%|
[php_commenters](#php_commenters)|385|385|385|100.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|366|100.0%|0.0%|
[malc0de](#malc0de)|342|342|342|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|282|1.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|234|62.9%|0.0%|
[zeus](#zeus)|233|233|204|87.5%|0.0%|
[zeus_badips](#zeus_badips)|203|203|181|89.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|153|92.7%|0.0%|
[openbl_1d](#openbl_1d)|141|141|139|98.5%|0.0%|
[dshield](#dshield)|20|5120|131|2.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|123|100.0%|0.0%|
[sslbl](#sslbl)|380|380|95|25.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|89|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|81|1.5%|0.0%|
[feodo](#feodo)|102|102|79|77.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|61|2.8%|0.0%|
[voipbl](#voipbl)|10507|10919|56|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|23|3.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|23|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|16|10.2%|0.0%|
[virbl](#virbl)|14|14|14|100.0%|0.0%|
[palevo](#palevo)|13|13|11|84.6%|0.0%|
[bogons](#bogons)|13|592708608|4|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|3|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|88|88|2|2.2%|0.0%|

## firehol_proxies

**FireHOL Proxies** - Known open proxies in the last 30 days. (includes: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy)

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **11678** entries, **11905** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|18197|82203|11905|14.4%|100.0%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|7245|100.0%|60.8%|
[firehol_level3](#firehol_level3)|107925|9625377|5319|0.0%|44.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|5256|5.6%|44.1%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|2637|100.0%|22.1%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2424|8.2%|20.3%|
[xroxy](#xroxy)|2138|2138|2138|100.0%|17.9%|
[proxyrss](#proxyrss)|1553|1553|1553|100.0%|13.0%|
[firehol_level2](#firehol_level2)|25559|37202|1193|3.2%|10.0%|
[proxz](#proxz)|1093|1093|1093|100.0%|9.1%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|892|11.9%|7.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.5%|
[blocklist_de](#blocklist_de)|31134|31134|610|1.9%|5.1%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|519|14.8%|4.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|485|0.0%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|373|0.0%|3.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|271|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|260|2.7%|2.1%|
[et_tor](#et_tor)|6400|6400|168|2.6%|1.4%|
[dm_tor](#dm_tor)|6345|6345|166|2.6%|1.3%|
[bm_tor](#bm_tor)|6369|6369|166|2.6%|1.3%|
[nixspam](#nixspam)|29888|29888|127|0.4%|1.0%|
[php_dictionary](#php_dictionary)|630|630|81|12.8%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|80|0.4%|0.6%|
[php_spammers](#php_spammers)|622|622|67|10.7%|0.5%|
[php_commenters](#php_commenters)|385|385|65|16.8%|0.5%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|32|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7199|7199|18|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|11|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|10|2.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|9|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|8|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|5|3.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|5|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[firehol_level1](#firehol_level1)|5091|688943669|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|3|0.1%|0.0%|
[et_block](#et_block)|999|18343755|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|3|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[shunlist](#shunlist)|1254|1254|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5091|688943669|670264216|97.2%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4235823|3.0%|0.6%|
[firehol_level3](#firehol_level3)|107925|9625377|566181|5.8%|0.0%|
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
[ciarmy](#ciarmy)|391|391|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|107925|9625377|23|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5091|688943669|18|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11678|11905|15|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|14|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|13|0.0%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[firehol_level2](#firehol_level2)|25559|37202|10|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31134|31134|10|0.0%|0.0%|
[nixspam](#nixspam)|29888|29888|9|0.0%|0.0%|
[et_block](#et_block)|999|18343755|9|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|6|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|5|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|4|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|4|0.0%|0.0%|
[xroxy](#xroxy)|2138|2138|3|0.1%|0.0%|
[php_dictionary](#php_dictionary)|630|630|3|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|3|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|1|0.0%|0.0%|
[proxz](#proxz)|1093|1093|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|107925|9625377|9177856|95.3%|100.0%|
[firehol_level1](#firehol_level1)|5091|688943669|7497728|1.0%|81.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6932480|37.8%|75.5%|
[et_block](#et_block)|999|18343755|6932480|37.7%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3720|670264216|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|719|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|518|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|157|0.5%|0.0%|
[nixspam](#nixspam)|29888|29888|142|0.4%|0.0%|
[firehol_level2](#firehol_level2)|25559|37202|70|0.1%|0.0%|
[blocklist_de](#blocklist_de)|31134|31134|47|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|37|1.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|28|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|7199|7199|17|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|12|0.1%|0.0%|
[openbl_30d](#openbl_30d)|2874|2874|12|0.4%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[zeus](#zeus)|233|233|10|4.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|6|0.2%|0.0%|
[openbl_7d](#openbl_7d)|824|824|5|0.6%|0.0%|
[et_compromised](#et_compromised)|1678|1678|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|5|0.2%|0.0%|
[php_dictionary](#php_dictionary)|630|630|4|0.6%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6345|6345|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6369|6369|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|4|0.0%|0.0%|
[shunlist](#shunlist)|1254|1254|3|0.2%|0.0%|
[php_spammers](#php_spammers)|622|622|3|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|3|1.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|3|0.1%|0.0%|
[openbl_1d](#openbl_1d)|141|141|2|1.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11678|11905|2|0.0%|0.0%|
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
[firehol_level1](#firehol_level1)|5091|688943669|2545681|0.3%|0.3%|
[et_block](#et_block)|999|18343755|2272541|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[firehol_level3](#firehol_level3)|107925|9625377|919946|9.5%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3720|670264216|239993|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|4131|2.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|3416|4.1%|0.0%|
[firehol_level2](#firehol_level2)|25559|37202|1682|4.5%|0.0%|
[blocklist_de](#blocklist_de)|31134|31134|1562|5.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1506|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|1407|7.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|1331|8.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|549|1.8%|0.0%|
[nixspam](#nixspam)|29888|29888|498|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[voipbl](#voipbl)|10507|10919|299|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11678|11905|271|2.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[openbl_60d](#openbl_60d)|7199|7199|168|2.3%|0.0%|
[et_tor](#et_tor)|6400|6400|166|2.5%|0.0%|
[bm_tor](#bm_tor)|6369|6369|164|2.5%|0.0%|
[dm_tor](#dm_tor)|6345|6345|163|2.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|142|1.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|130|1.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|107|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|80|3.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|67|2.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[openbl_30d](#openbl_30d)|2874|2874|64|2.2%|0.0%|
[xroxy](#xroxy)|2138|2138|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|51|2.9%|0.0%|
[et_compromised](#et_compromised)|1678|1678|46|2.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|44|0.8%|0.0%|
[et_botcc](#et_botcc)|509|509|40|7.8%|0.0%|
[proxz](#proxz)|1093|1093|39|3.5%|0.0%|
[proxyrss](#proxyrss)|1553|1553|35|2.2%|0.0%|
[ciarmy](#ciarmy)|391|391|34|8.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|29|0.8%|0.0%|
[shunlist](#shunlist)|1254|1254|26|2.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|23|1.0%|0.0%|
[openbl_7d](#openbl_7d)|824|824|19|2.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[php_harvesters](#php_harvesters)|366|366|11|3.0%|0.0%|
[php_dictionary](#php_dictionary)|630|630|11|1.7%|0.0%|
[malc0de](#malc0de)|342|342|11|3.2%|0.0%|
[php_commenters](#php_commenters)|385|385|10|2.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|10|8.1%|0.0%|
[php_spammers](#php_spammers)|622|622|9|1.4%|0.0%|
[zeus](#zeus)|233|233|6|2.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|88|88|6|6.8%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|4|1.9%|0.0%|
[openbl_1d](#openbl_1d)|141|141|4|2.8%|0.0%|
[sslbl](#sslbl)|380|380|3|0.7%|0.0%|
[feodo](#feodo)|102|102|3|2.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|1|0.6%|0.0%|

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
[firehol_level1](#firehol_level1)|5091|688943669|8864898|1.2%|2.5%|
[et_block](#et_block)|999|18343755|8533288|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[firehol_level3](#firehol_level3)|107925|9625377|2537295|26.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3720|670264216|249087|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|6255|3.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|2879|3.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2475|2.6%|0.0%|
[firehol_level2](#firehol_level2)|25559|37202|1772|4.7%|0.0%|
[blocklist_de](#blocklist_de)|31134|31134|1607|5.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|1251|6.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|1099|6.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|825|2.8%|0.0%|
[dshield](#dshield)|20|5120|768|15.0%|0.0%|
[nixspam](#nixspam)|29888|29888|549|1.8%|0.0%|
[voipbl](#voipbl)|10507|10919|434|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|11678|11905|373|3.1%|0.0%|
[openbl_60d](#openbl_60d)|7199|7199|327|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|212|2.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|211|2.9%|0.0%|
[et_tor](#et_tor)|6400|6400|186|2.9%|0.0%|
[dm_tor](#dm_tor)|6345|6345|183|2.8%|0.0%|
[bm_tor](#bm_tor)|6369|6369|182|2.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|163|1.6%|0.0%|
[openbl_30d](#openbl_30d)|2874|2874|152|5.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|139|4.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|125|3.5%|0.0%|
[xroxy](#xroxy)|2138|2138|104|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|101|3.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|90|5.2%|0.0%|
[et_compromised](#et_compromised)|1678|1678|86|5.1%|0.0%|
[shunlist](#shunlist)|1254|1254|71|5.6%|0.0%|
[proxyrss](#proxyrss)|1553|1553|66|4.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|65|1.2%|0.0%|
[php_spammers](#php_spammers)|622|622|51|8.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|50|2.3%|0.0%|
[openbl_7d](#openbl_7d)|824|824|47|5.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[ciarmy](#ciarmy)|391|391|44|11.2%|0.0%|
[proxz](#proxz)|1093|1093|43|3.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[php_dictionary](#php_dictionary)|630|630|22|3.4%|0.0%|
[et_botcc](#et_botcc)|509|509|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[malc0de](#malc0de)|342|342|20|5.8%|0.0%|
[php_commenters](#php_commenters)|385|385|15|3.8%|0.0%|
[openbl_1d](#openbl_1d)|141|141|11|7.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|10|6.4%|0.0%|
[zeus](#zeus)|233|233|9|3.8%|0.0%|
[php_harvesters](#php_harvesters)|366|366|9|2.4%|0.0%|
[zeus_badips](#zeus_badips)|203|203|8|3.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|88|88|8|9.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|6|3.6%|0.0%|
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
[firehol_level1](#firehol_level1)|5091|688943669|4637028|0.6%|3.3%|
[fullbogons](#fullbogons)|3720|670264216|4235823|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[firehol_level3](#firehol_level3)|107925|9625377|161468|1.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[et_block](#et_block)|999|18343755|130394|0.7%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|13855|7.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|5744|6.2%|0.0%|
[firehol_level2](#firehol_level2)|25559|37202|4111|11.0%|0.0%|
[blocklist_de](#blocklist_de)|31134|31134|3644|11.7%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|2831|3.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|2617|13.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|2430|15.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1893|6.4%|0.0%|
[voipbl](#voipbl)|10507|10919|1600|14.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[nixspam](#nixspam)|29888|29888|1073|3.5%|0.0%|
[openbl_60d](#openbl_60d)|7199|7199|741|10.2%|0.0%|
[et_tor](#et_tor)|6400|6400|623|9.7%|0.0%|
[bm_tor](#bm_tor)|6369|6369|619|9.7%|0.0%|
[dm_tor](#dm_tor)|6345|6345|614|9.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|532|7.1%|0.0%|
[firehol_proxies](#firehol_proxies)|11678|11905|485|4.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|379|7.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|361|12.4%|0.0%|
[openbl_30d](#openbl_30d)|2874|2874|293|10.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|254|2.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|233|6.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|201|2.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|195|9.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|153|8.9%|0.0%|
[et_compromised](#et_compromised)|1678|1678|151|8.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[shunlist](#shunlist)|1254|1254|114|9.0%|0.0%|
[openbl_7d](#openbl_7d)|824|824|109|13.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[xroxy](#xroxy)|2138|2138|105|4.9%|0.0%|
[proxz](#proxz)|1093|1093|93|8.5%|0.0%|
[et_botcc](#et_botcc)|509|509|80|15.7%|0.0%|
[ciarmy](#ciarmy)|391|391|79|20.2%|0.0%|
[proxyrss](#proxyrss)|1553|1553|61|3.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|55|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[malc0de](#malc0de)|342|342|48|14.0%|0.0%|
[php_spammers](#php_spammers)|622|622|37|5.9%|0.0%|
[php_dictionary](#php_dictionary)|630|630|33|5.2%|0.0%|
[sslbl](#sslbl)|380|380|30|7.8%|0.0%|
[php_commenters](#php_commenters)|385|385|24|6.2%|0.0%|
[php_harvesters](#php_harvesters)|366|366|19|5.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|17|10.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|16|9.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|88|88|16|18.1%|0.0%|
[zeus](#zeus)|233|233|14|6.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|12|9.7%|0.0%|
[openbl_1d](#openbl_1d)|141|141|11|7.8%|0.0%|
[feodo](#feodo)|102|102|11|10.7%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[virbl](#virbl)|14|14|1|7.1%|0.0%|
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
[firehol_proxies](#firehol_proxies)|11678|11905|663|5.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|663|0.8%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[firehol_level3](#firehol_level3)|107925|9625377|23|0.0%|3.4%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|18|0.0%|2.7%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|14|0.1%|2.1%|
[xroxy](#xroxy)|2138|2138|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|13|0.0%|1.9%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1553|1553|8|0.5%|1.2%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|7|0.2%|1.0%|
[proxz](#proxz)|1093|1093|6|0.5%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|5|0.0%|0.7%|
[firehol_level2](#firehol_level2)|25559|37202|5|0.0%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|3|0.0%|0.4%|
[blocklist_de](#blocklist_de)|31134|31134|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.3%|
[nixspam](#nixspam)|29888|29888|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5091|688943669|2|0.0%|0.3%|
[et_block](#et_block)|999|18343755|2|0.0%|0.3%|
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
[firehol_level3](#firehol_level3)|107925|9625377|339173|3.5%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5091|688943669|1931|0.0%|0.5%|
[et_block](#et_block)|999|18343755|1041|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3720|670264216|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|48|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|28|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|22|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6345|6345|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6369|6369|22|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[nixspam](#nixspam)|29888|29888|17|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|15|0.1%|0.0%|
[firehol_level2](#firehol_level2)|25559|37202|14|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11678|11905|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|10|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7199|7199|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10507|10919|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31134|31134|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2874|2874|3|0.1%|0.0%|
[malc0de](#malc0de)|342|342|3|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|3|0.0%|0.0%|
[proxyrss](#proxyrss)|1553|1553|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|88|88|2|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[xroxy](#xroxy)|2138|2138|1|0.0%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|1|0.0%|0.0%|
[proxz](#proxz)|1093|1093|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|630|630|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[feodo](#feodo)|102|102|1|0.9%|0.0%|
[ciarmy](#ciarmy)|391|391|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|107925|9625377|1450|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5091|688943669|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3720|670264216|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|10|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.4%|
[et_block](#et_block)|999|18343755|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|11678|11905|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7199|7199|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2874|2874|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[firehol_level2](#firehol_level2)|25559|37202|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|824|824|1|0.1%|0.0%|
[nixspam](#nixspam)|29888|29888|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|31134|31134|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|107925|9625377|342|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|48|0.0%|14.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|20|0.0%|5.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.2%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|10|0.0%|2.9%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|8|6.5%|2.3%|
[firehol_level1](#firehol_level1)|5091|688943669|7|0.0%|2.0%|
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
[firehol_level3](#firehol_level3)|107925|9625377|1288|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5091|688943669|38|0.0%|2.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|29|0.0%|2.2%|
[et_block](#et_block)|999|18343755|29|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|28|0.2%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3720|670264216|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|7|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|4|0.0%|0.3%|
[malc0de](#malc0de)|342|342|4|1.1%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[nixspam](#nixspam)|29888|29888|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|1|0.8%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Tue Jun  9 01:09:28 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11678|11905|372|3.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|372|0.4%|100.0%|
[firehol_level3](#firehol_level3)|107925|9625377|234|0.0%|62.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|233|0.2%|62.6%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|192|0.6%|51.6%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|172|1.7%|46.2%|
[et_tor](#et_tor)|6400|6400|165|2.5%|44.3%|
[dm_tor](#dm_tor)|6345|6345|163|2.5%|43.8%|
[bm_tor](#bm_tor)|6369|6369|163|2.5%|43.8%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|157|2.1%|42.2%|
[firehol_level2](#firehol_level2)|25559|37202|157|0.4%|42.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|125|0.0%|33.6%|
[php_commenters](#php_commenters)|385|385|40|10.3%|10.7%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7199|7199|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|366|366|6|1.6%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|4|0.0%|1.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|1.0%|
[php_dictionary](#php_dictionary)|630|630|4|0.6%|1.0%|
[nixspam](#nixspam)|29888|29888|2|0.0%|0.5%|
[xroxy](#xroxy)|2138|2138|1|0.0%|0.2%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.2%|
[shunlist](#shunlist)|1254|1254|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|1|0.0%|0.2%|
[et_block](#et_block)|999|18343755|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|31134|31134|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Tue Jun  9 03:30:02 UTC 2015.

The ipset `nixspam` has **29888** entries, **29888** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1073|0.0%|3.5%|
[firehol_level2](#firehol_level2)|25559|37202|731|1.9%|2.4%|
[blocklist_de](#blocklist_de)|31134|31134|710|2.2%|2.3%|
[firehol_level3](#firehol_level3)|107925|9625377|667|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|627|3.2%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|549|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|498|0.0%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|302|3.1%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|241|0.2%|0.8%|
[firehol_level1](#firehol_level1)|5091|688943669|147|0.0%|0.4%|
[et_block](#et_block)|999|18343755|143|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|142|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|142|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|136|0.4%|0.4%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|132|0.1%|0.4%|
[firehol_proxies](#firehol_proxies)|11678|11905|127|1.0%|0.4%|
[php_dictionary](#php_dictionary)|630|630|97|15.3%|0.3%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|91|1.2%|0.3%|
[php_spammers](#php_spammers)|622|622|83|13.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|78|1.0%|0.2%|
[xroxy](#xroxy)|2138|2138|59|2.7%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|50|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|49|1.4%|0.1%|
[proxz](#proxz)|1093|1093|35|3.2%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|32|0.6%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|30|0.1%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|22|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|17|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|11|3.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|9|0.3%|0.0%|
[proxyrss](#proxyrss)|1553|1553|9|0.5%|0.0%|
[php_commenters](#php_commenters)|385|385|9|2.3%|0.0%|
[openbl_60d](#openbl_60d)|7199|7199|9|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|9|0.0%|0.0%|
[dm_tor](#dm_tor)|6345|6345|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6369|6369|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2874|2874|4|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|4|2.4%|0.0%|
[shunlist](#shunlist)|1254|1254|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|824|824|2|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_compromised](#et_compromised)|1678|1678|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[voipbl](#voipbl)|10507|10919|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Tue Jun  9 03:32:00 UTC 2015.

The ipset `openbl_1d` has **141** entries, **141** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25559|37202|141|0.3%|100.0%|
[firehol_level3](#firehol_level3)|107925|9625377|139|0.0%|98.5%|
[openbl_60d](#openbl_60d)|7199|7199|138|1.9%|97.8%|
[openbl_30d](#openbl_30d)|2874|2874|138|4.8%|97.8%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|134|0.0%|95.0%|
[openbl_7d](#openbl_7d)|824|824|132|16.0%|93.6%|
[blocklist_de](#blocklist_de)|31134|31134|114|0.3%|80.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|112|3.8%|79.4%|
[shunlist](#shunlist)|1254|1254|68|5.4%|48.2%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|63|3.6%|44.6%|
[et_compromised](#et_compromised)|1678|1678|54|3.2%|38.2%|
[firehol_level1](#firehol_level1)|5091|688943669|21|0.0%|14.8%|
[et_block](#et_block)|999|18343755|18|0.0%|12.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|17|10.3%|12.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|11.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|11|0.0%|7.8%|
[dshield](#dshield)|20|5120|11|0.2%|7.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|2.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|1.4%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|2|0.0%|1.4%|
[ciarmy](#ciarmy)|391|391|1|0.2%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|1|0.0%|0.7%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Tue Jun  9 00:07:00 UTC 2015.

The ipset `openbl_30d` has **2874** entries, **2874** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7199|7199|2874|39.9%|100.0%|
[firehol_level3](#firehol_level3)|107925|9625377|2874|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|2856|1.5%|99.3%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|933|54.3%|32.4%|
[et_compromised](#et_compromised)|1678|1678|918|54.7%|31.9%|
[firehol_level2](#firehol_level2)|25559|37202|881|2.3%|30.6%|
[blocklist_de](#blocklist_de)|31134|31134|853|2.7%|29.6%|
[openbl_7d](#openbl_7d)|824|824|824|100.0%|28.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|808|27.9%|28.1%|
[shunlist](#shunlist)|1254|1254|526|41.9%|18.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|293|0.0%|10.1%|
[firehol_level1](#firehol_level1)|5091|688943669|166|0.0%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|152|0.0%|5.2%|
[openbl_1d](#openbl_1d)|141|141|138|97.8%|4.8%|
[et_block](#et_block)|999|18343755|127|0.0%|4.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|120|0.0%|4.1%|
[dshield](#dshield)|20|5120|112|2.1%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|64|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|41|0.2%|1.4%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|32|1.5%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|25|15.1%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|6|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|4|0.0%|0.1%|
[nixspam](#nixspam)|29888|29888|4|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|2|1.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|2|0.0%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|1|0.0%|0.0%|
[ciarmy](#ciarmy)|391|391|1|0.2%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Tue Jun  9 00:07:00 UTC 2015.

The ipset `openbl_60d` has **7199** entries, **7199** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178836|178836|7175|4.0%|99.6%|
[firehol_level3](#firehol_level3)|107925|9625377|3006|0.0%|41.7%|
[openbl_30d](#openbl_30d)|2874|2874|2874|100.0%|39.9%|
[firehol_level2](#firehol_level2)|25559|37202|1129|3.0%|15.6%|
[blocklist_de](#blocklist_de)|31134|31134|1081|3.4%|15.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|1012|35.0%|14.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|994|57.8%|13.8%|
[et_compromised](#et_compromised)|1678|1678|980|58.4%|13.6%|
[openbl_7d](#openbl_7d)|824|824|824|100.0%|11.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|741|0.0%|10.2%|
[shunlist](#shunlist)|1254|1254|554|44.1%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|327|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5091|688943669|304|0.0%|4.2%|
[et_block](#et_block)|999|18343755|250|0.0%|3.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|239|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|168|0.0%|2.3%|
[openbl_1d](#openbl_1d)|141|141|138|97.8%|1.9%|
[dshield](#dshield)|20|5120|130|2.5%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|52|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|49|0.2%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|37|1.7%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|28|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|26|15.7%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|25|0.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|23|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|21|0.2%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6345|6345|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6369|6369|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[firehol_proxies](#firehol_proxies)|11678|11905|18|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|17|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|16|0.4%|0.2%|
[php_commenters](#php_commenters)|385|385|10|2.5%|0.1%|
[nixspam](#nixspam)|29888|29888|9|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|8|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[zeus](#zeus)|233|233|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|2|1.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.0%|
[ciarmy](#ciarmy)|391|391|1|0.2%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Tue Jun  9 00:07:00 UTC 2015.

The ipset `openbl_7d` has **824** entries, **824** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7199|7199|824|11.4%|100.0%|
[openbl_30d](#openbl_30d)|2874|2874|824|28.6%|100.0%|
[firehol_level3](#firehol_level3)|107925|9625377|824|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|816|0.4%|99.0%|
[firehol_level2](#firehol_level2)|25559|37202|426|1.1%|51.6%|
[blocklist_de](#blocklist_de)|31134|31134|400|1.2%|48.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|387|13.3%|46.9%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|317|18.4%|38.4%|
[et_compromised](#et_compromised)|1678|1678|307|18.2%|37.2%|
[shunlist](#shunlist)|1254|1254|218|17.3%|26.4%|
[openbl_1d](#openbl_1d)|141|141|132|93.6%|16.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|109|0.0%|13.2%|
[firehol_level1](#firehol_level1)|5091|688943669|53|0.0%|6.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|47|0.0%|5.7%|
[et_block](#et_block)|999|18343755|46|0.0%|5.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|42|0.0%|5.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|24|14.5%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|19|0.0%|2.3%|
[dshield](#dshield)|20|5120|18|0.3%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|12|0.0%|1.4%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|11|0.5%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|3|0.0%|0.3%|
[nixspam](#nixspam)|29888|29888|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|1|0.0%|0.1%|
[php_spammers](#php_spammers)|622|622|1|0.1%|0.1%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|
[ciarmy](#ciarmy)|391|391|1|0.2%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|1|0.6%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  9 03:18:21 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5091|688943669|13|0.0%|100.0%|
[et_block](#et_block)|999|18343755|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|11|0.1%|84.6%|
[firehol_level3](#firehol_level3)|107925|9625377|11|0.0%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Tue Jun  9 03:27:07 UTC 2015.

The ipset `php_commenters` has **385** entries, **385** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107925|9625377|385|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|289|0.3%|75.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|215|0.7%|55.8%|
[firehol_level2](#firehol_level2)|25559|37202|180|0.4%|46.7%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|160|2.1%|41.5%|
[blocklist_de](#blocklist_de)|31134|31134|93|0.2%|24.1%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|76|2.1%|19.7%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|71|0.0%|18.4%|
[firehol_proxies](#firehol_proxies)|11678|11905|65|0.5%|16.8%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|51|0.5%|13.2%|
[et_tor](#et_tor)|6400|6400|43|0.6%|11.1%|
[dm_tor](#dm_tor)|6345|6345|43|0.6%|11.1%|
[bm_tor](#bm_tor)|6369|6369|43|0.6%|11.1%|
[php_spammers](#php_spammers)|622|622|42|6.7%|10.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|42|25.4%|10.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|40|10.7%|10.3%|
[firehol_level1](#firehol_level1)|5091|688943669|37|0.0%|9.6%|
[et_block](#et_block)|999|18343755|30|0.0%|7.7%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|30|0.1%|7.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|29|0.0%|7.5%|
[php_dictionary](#php_dictionary)|630|630|26|4.1%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|24|0.0%|6.2%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|24|0.1%|6.2%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|23|0.3%|5.9%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|17|0.0%|4.4%|
[php_harvesters](#php_harvesters)|366|366|15|4.0%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|15|0.0%|3.8%|
[openbl_60d](#openbl_60d)|7199|7199|10|0.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|10|0.0%|2.5%|
[nixspam](#nixspam)|29888|29888|9|0.0%|2.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|9|0.1%|2.3%|
[xroxy](#xroxy)|2138|2138|8|0.3%|2.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|1.8%|
[proxz](#proxz)|1093|1093|7|0.6%|1.8%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|5|0.1%|1.2%|
[proxyrss](#proxyrss)|1553|1553|2|0.1%|0.5%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.2%|
[zeus](#zeus)|233|233|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|824|824|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|2874|2874|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Tue Jun  9 03:27:07 UTC 2015.

The ipset `php_dictionary` has **630** entries, **630** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107925|9625377|630|0.0%|100.0%|
[php_spammers](#php_spammers)|622|622|243|39.0%|38.5%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|119|0.1%|18.8%|
[nixspam](#nixspam)|29888|29888|97|0.3%|15.3%|
[firehol_level2](#firehol_level2)|25559|37202|96|0.2%|15.2%|
[blocklist_de](#blocklist_de)|31134|31134|90|0.2%|14.2%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|85|0.8%|13.4%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|82|0.0%|13.0%|
[firehol_proxies](#firehol_proxies)|11678|11905|81|0.6%|12.8%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|77|0.2%|12.2%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|61|0.3%|9.6%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|54|0.7%|8.5%|
[xroxy](#xroxy)|2138|2138|38|1.7%|6.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|34|0.4%|5.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|33|0.0%|5.2%|
[php_commenters](#php_commenters)|385|385|26|6.7%|4.1%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|24|0.6%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|22|0.0%|3.4%|
[proxz](#proxz)|1093|1093|21|1.9%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|1.7%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|8|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.9%|
[firehol_level1](#firehol_level1)|5091|688943669|6|0.0%|0.9%|
[et_block](#et_block)|999|18343755|6|0.0%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|5|0.0%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|5|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|4|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|4|2.4%|0.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.4%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.4%|
[dm_tor](#dm_tor)|6345|6345|3|0.0%|0.4%|
[bm_tor](#bm_tor)|6369|6369|3|0.0%|0.4%|
[proxyrss](#proxyrss)|1553|1553|2|0.1%|0.3%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|1|0.0%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Tue Jun  9 03:27:05 UTC 2015.

The ipset `php_harvesters` has **366** entries, **366** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107925|9625377|366|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|81|0.0%|22.1%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|61|0.2%|16.6%|
[firehol_level2](#firehol_level2)|25559|37202|57|0.1%|15.5%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|42|0.5%|11.4%|
[blocklist_de](#blocklist_de)|31134|31134|42|0.1%|11.4%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|31|0.8%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|19|0.0%|5.1%|
[php_commenters](#php_commenters)|385|385|15|3.8%|4.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|14|0.1%|3.8%|
[nixspam](#nixspam)|29888|29888|11|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|11|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|11|0.0%|3.0%|
[firehol_proxies](#firehol_proxies)|11678|11905|10|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.4%|
[et_tor](#et_tor)|6400|6400|7|0.1%|1.9%|
[dm_tor](#dm_tor)|6345|6345|7|0.1%|1.9%|
[bm_tor](#bm_tor)|6369|6369|7|0.1%|1.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|6|3.8%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|4|0.0%|1.0%|
[firehol_level1](#firehol_level1)|5091|688943669|3|0.0%|0.8%|
[xroxy](#xroxy)|2138|2138|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|2|0.0%|0.5%|
[php_spammers](#php_spammers)|622|622|2|0.3%|0.5%|
[php_dictionary](#php_dictionary)|630|630|2|0.3%|0.5%|
[openbl_60d](#openbl_60d)|7199|7199|2|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|2|1.2%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[et_block](#et_block)|999|18343755|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Tue Jun  9 03:27:06 UTC 2015.

The ipset `php_spammers` has **622** entries, **622** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107925|9625377|622|0.0%|100.0%|
[php_dictionary](#php_dictionary)|630|630|243|38.5%|39.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|131|0.1%|21.0%|
[firehol_level2](#firehol_level2)|25559|37202|97|0.2%|15.5%|
[nixspam](#nixspam)|29888|29888|83|0.2%|13.3%|
[blocklist_de](#blocklist_de)|31134|31134|83|0.2%|13.3%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|82|0.8%|13.1%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|77|0.2%|12.3%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|69|0.0%|11.0%|
[firehol_proxies](#firehol_proxies)|11678|11905|67|0.5%|10.7%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|57|0.2%|9.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|51|0.0%|8.1%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|45|0.6%|7.2%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|45|0.6%|7.2%|
[php_commenters](#php_commenters)|385|385|42|10.9%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|37|0.0%|5.9%|
[xroxy](#xroxy)|2138|2138|30|1.4%|4.8%|
[proxz](#proxz)|1093|1093|20|1.8%|3.2%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|18|0.5%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|9|0.0%|1.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|7|0.1%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|7|0.0%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|6|3.6%|0.9%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|5|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[firehol_level1](#firehol_level1)|5091|688943669|4|0.0%|0.6%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.6%|
[et_block](#et_block)|999|18343755|4|0.0%|0.6%|
[dm_tor](#dm_tor)|6345|6345|4|0.0%|0.6%|
[bm_tor](#bm_tor)|6369|6369|4|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|3|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[proxyrss](#proxyrss)|1553|1553|2|0.1%|0.3%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.3%|
[openbl_7d](#openbl_7d)|824|824|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7199|7199|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|2874|2874|1|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|1|0.0%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Tue Jun  9 02:31:32 UTC 2015.

The ipset `proxyrss` has **1553** entries, **1553** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11678|11905|1553|13.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|1553|1.8%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|778|0.8%|50.0%|
[firehol_level3](#firehol_level3)|107925|9625377|778|0.0%|50.0%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|628|8.6%|40.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|610|2.0%|39.2%|
[firehol_level2](#firehol_level2)|25559|37202|414|1.1%|26.6%|
[xroxy](#xroxy)|2138|2138|374|17.4%|24.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|349|4.6%|22.4%|
[proxz](#proxz)|1093|1093|241|22.0%|15.5%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|237|8.9%|15.2%|
[blocklist_de](#blocklist_de)|31134|31134|210|0.6%|13.5%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|208|5.9%|13.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|66|0.0%|4.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|61|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|35|0.0%|2.2%|
[nixspam](#nixspam)|29888|29888|9|0.0%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|8|1.2%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|4|2.4%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|3|0.0%|0.1%|
[php_spammers](#php_spammers)|622|622|2|0.3%|0.1%|
[php_dictionary](#php_dictionary)|630|630|2|0.3%|0.1%|
[php_commenters](#php_commenters)|385|385|2|0.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.1%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Tue Jun  9 02:31:38 UTC 2015.

The ipset `proxz` has **1093** entries, **1093** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11678|11905|1093|9.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|1093|1.3%|100.0%|
[firehol_level3](#firehol_level3)|107925|9625377|663|0.0%|60.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|657|0.7%|60.1%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|496|6.8%|45.3%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|470|1.6%|43.0%|
[xroxy](#xroxy)|2138|2138|399|18.6%|36.5%|
[firehol_level2](#firehol_level2)|25559|37202|253|0.6%|23.1%|
[proxyrss](#proxyrss)|1553|1553|241|15.5%|22.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|192|2.5%|17.5%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|185|7.0%|16.9%|
[blocklist_de](#blocklist_de)|31134|31134|159|0.5%|14.5%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|139|3.9%|12.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|93|0.0%|8.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|43|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|39|0.0%|3.5%|
[nixspam](#nixspam)|29888|29888|35|0.1%|3.2%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|24|0.2%|2.1%|
[php_dictionary](#php_dictionary)|630|630|21|3.3%|1.9%|
[php_spammers](#php_spammers)|622|622|20|3.2%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|18|0.0%|1.6%|
[php_commenters](#php_commenters)|385|385|7|1.8%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|3|1.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|3|0.0%|0.2%|
[et_compromised](#et_compromised)|1678|1678|2|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|1|0.0%|0.0%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Tue Jun  9 01:47:43 UTC 2015.

The ipset `ri_connect_proxies` has **2637** entries, **2637** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11678|11905|2637|22.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|2637|3.2%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1499|1.6%|56.8%|
[firehol_level3](#firehol_level3)|107925|9625377|1499|0.0%|56.8%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|1113|15.3%|42.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|615|2.1%|23.3%|
[xroxy](#xroxy)|2138|2138|382|17.8%|14.4%|
[proxyrss](#proxyrss)|1553|1553|237|15.2%|8.9%|
[firehol_level2](#firehol_level2)|25559|37202|190|0.5%|7.2%|
[proxz](#proxz)|1093|1093|185|16.9%|7.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|141|1.8%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|101|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|80|0.0%|3.0%|
[blocklist_de](#blocklist_de)|31134|31134|79|0.2%|2.9%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|75|2.1%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|55|0.0%|2.0%|
[nixspam](#nixspam)|29888|29888|9|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|6|0.0%|0.2%|
[php_commenters](#php_commenters)|385|385|5|1.2%|0.1%|
[php_dictionary](#php_dictionary)|630|630|4|0.6%|0.1%|
[php_spammers](#php_spammers)|622|622|3|0.4%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|3|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Tue Jun  9 01:47:35 UTC 2015.

The ipset `ri_web_proxies` has **7245** entries, **7245** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11678|11905|7245|60.8%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|7245|8.8%|100.0%|
[firehol_level3](#firehol_level3)|107925|9625377|3508|0.0%|48.4%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|3460|3.7%|47.7%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1566|5.3%|21.6%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|1113|42.2%|15.3%|
[xroxy](#xroxy)|2138|2138|934|43.6%|12.8%|
[firehol_level2](#firehol_level2)|25559|37202|708|1.9%|9.7%|
[proxyrss](#proxyrss)|1553|1553|628|40.4%|8.6%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|518|6.9%|7.1%|
[proxz](#proxz)|1093|1093|496|45.3%|6.8%|
[blocklist_de](#blocklist_de)|31134|31134|417|1.3%|5.7%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|355|10.1%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|211|0.0%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|201|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|142|0.0%|1.9%|
[nixspam](#nixspam)|29888|29888|91|0.3%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|64|0.6%|0.8%|
[php_dictionary](#php_dictionary)|630|630|54|8.5%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|52|0.2%|0.7%|
[php_spammers](#php_spammers)|622|622|45|7.2%|0.6%|
[php_commenters](#php_commenters)|385|385|23|5.9%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|14|2.1%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|8|0.1%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|7|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|4|2.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|4|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6345|6345|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6369|6369|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5091|688943669|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Tue Jun  9 03:30:06 UTC 2015.

The ipset `shunlist` has **1254** entries, **1254** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107925|9625377|1254|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|1239|0.6%|98.8%|
[openbl_60d](#openbl_60d)|7199|7199|554|7.6%|44.1%|
[openbl_30d](#openbl_30d)|2874|2874|526|18.3%|41.9%|
[firehol_level2](#firehol_level2)|25559|37202|450|1.2%|35.8%|
[blocklist_de](#blocklist_de)|31134|31134|444|1.4%|35.4%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|432|25.1%|34.4%|
[et_compromised](#et_compromised)|1678|1678|413|24.6%|32.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|409|14.1%|32.6%|
[openbl_7d](#openbl_7d)|824|824|218|26.4%|17.3%|
[firehol_level1](#firehol_level1)|5091|688943669|192|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|114|0.0%|9.0%|
[dshield](#dshield)|20|5120|104|2.0%|8.2%|
[et_block](#et_block)|999|18343755|103|0.0%|8.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|95|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|71|0.0%|5.6%|
[openbl_1d](#openbl_1d)|141|141|68|48.2%|5.4%|
[sslbl](#sslbl)|380|380|64|16.8%|5.1%|
[ciarmy](#ciarmy)|391|391|31|7.9%|2.4%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|30|0.1%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|26|0.0%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|22|13.3%|1.7%|
[voipbl](#voipbl)|10507|10919|12|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|4|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|4|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[nixspam](#nixspam)|29888|29888|2|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[firehol_proxies](#firehol_proxies)|11678|11905|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6345|6345|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6369|6369|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|1|0.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|107925|9625377|9624|0.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|1133|1.3%|11.7%|
[et_tor](#et_tor)|6400|6400|1083|16.9%|11.2%|
[bm_tor](#bm_tor)|6369|6369|1029|16.1%|10.6%|
[dm_tor](#dm_tor)|6345|6345|1021|16.0%|10.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|815|0.8%|8.4%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|668|2.2%|6.9%|
[firehol_level2](#firehol_level2)|25559|37202|661|1.7%|6.8%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|400|5.3%|4.1%|
[nixspam](#nixspam)|29888|29888|302|1.0%|3.1%|
[et_block](#et_block)|999|18343755|301|0.0%|3.1%|
[blocklist_de](#blocklist_de)|31134|31134|300|0.9%|3.1%|
[firehol_level1](#firehol_level1)|5091|688943669|299|0.0%|3.1%|
[firehol_proxies](#firehol_proxies)|11678|11905|260|2.1%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|260|1.3%|2.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|254|0.0%|2.6%|
[zeus](#zeus)|233|233|202|86.6%|2.0%|
[zeus_badips](#zeus_badips)|203|203|179|88.1%|1.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|172|46.2%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|163|0.0%|1.6%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|123|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|107|0.0%|1.1%|
[php_dictionary](#php_dictionary)|630|630|85|13.4%|0.8%|
[php_spammers](#php_spammers)|622|622|82|13.1%|0.8%|
[feodo](#feodo)|102|102|79|77.4%|0.8%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|64|0.8%|0.6%|
[php_commenters](#php_commenters)|385|385|51|13.2%|0.5%|
[xroxy](#xroxy)|2138|2138|38|1.7%|0.3%|
[sslbl](#sslbl)|380|380|31|8.1%|0.3%|
[openbl_60d](#openbl_60d)|7199|7199|28|0.3%|0.2%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|28|2.1%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|28|0.8%|0.2%|
[proxz](#proxz)|1093|1093|24|2.1%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|20|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|15|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|15|0.7%|0.1%|
[php_harvesters](#php_harvesters)|366|366|14|3.8%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|13|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|9|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|6|0.2%|0.0%|
[openbl_30d](#openbl_30d)|2874|2874|6|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|4|3.2%|0.0%|
[shunlist](#shunlist)|1254|1254|3|0.2%|0.0%|
[proxyrss](#proxyrss)|1553|1553|3|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|2|1.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|2|0.0%|0.0%|
[openbl_7d](#openbl_7d)|824|824|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|1|0.6%|0.0%|

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
[firehol_level1](#firehol_level1)|5091|688943669|18338560|2.6%|100.0%|
[et_block](#et_block)|999|18343755|18338560|99.9%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[firehol_level3](#firehol_level3)|107925|9625377|6933030|72.0%|37.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3720|670264216|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|1374|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1008|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|307|1.0%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[firehol_level2](#firehol_level2)|25559|37202|250|0.6%|0.0%|
[openbl_60d](#openbl_60d)|7199|7199|239|3.3%|0.0%|
[blocklist_de](#blocklist_de)|31134|31134|189|0.6%|0.0%|
[nixspam](#nixspam)|29888|29888|142|0.4%|0.0%|
[openbl_30d](#openbl_30d)|2874|2874|120|4.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|116|4.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|101|6.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|101|5.8%|0.0%|
[shunlist](#shunlist)|1254|1254|95|7.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|78|1.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|46|1.3%|0.0%|
[openbl_7d](#openbl_7d)|824|824|42|5.0%|0.0%|
[php_commenters](#php_commenters)|385|385|29|7.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|22|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|20|0.2%|0.0%|
[zeus_badips](#zeus_badips)|203|203|16|7.8%|0.0%|
[zeus](#zeus)|233|233|16|6.8%|0.0%|
[openbl_1d](#openbl_1d)|141|141|16|11.3%|0.0%|
[voipbl](#voipbl)|10507|10919|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|14|0.6%|0.0%|
[php_dictionary](#php_dictionary)|630|630|6|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|5|3.0%|0.0%|
[php_spammers](#php_spammers)|622|622|4|0.6%|0.0%|
[malc0de](#malc0de)|342|342|4|1.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6345|6345|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6369|6369|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11678|11905|2|0.0%|0.0%|
[sslbl](#sslbl)|380|380|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[et_botcc](#et_botcc)|509|509|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|88|88|1|1.1%|0.0%|

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
[firehol_level1](#firehol_level1)|5091|688943669|487424|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[et_block](#et_block)|999|18343755|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|512|0.0%|0.1%|
[firehol_level3](#firehol_level3)|107925|9625377|89|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|78|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|15|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|9|0.0%|0.0%|
[firehol_level2](#firehol_level2)|25559|37202|8|0.0%|0.0%|
[php_commenters](#php_commenters)|385|385|7|1.8%|0.0%|
[blocklist_de](#blocklist_de)|31134|31134|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|5|2.4%|0.0%|
[zeus](#zeus)|233|233|5|2.1%|0.0%|
[nixspam](#nixspam)|29888|29888|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|3|1.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|2|0.0%|0.0%|
[virbl](#virbl)|14|14|1|7.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|366|366|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7199|7199|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2874|2874|1|0.0%|0.0%|
[malc0de](#malc0de)|342|342|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|123|123|1|0.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Tue Jun  9 03:15:06 UTC 2015.

The ipset `sslbl` has **380** entries, **380** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5091|688943669|380|0.0%|100.0%|
[firehol_level3](#firehol_level3)|107925|9625377|95|0.0%|25.0%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|68|0.0%|17.8%|
[shunlist](#shunlist)|1254|1254|64|5.1%|16.8%|
[feodo](#feodo)|102|102|37|36.2%|9.7%|
[et_block](#et_block)|999|18343755|37|0.0%|9.7%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|31|0.3%|8.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|30|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|4|0.0%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11678|11905|1|0.0%|0.2%|
[firehol_level2](#firehol_level2)|25559|37202|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|31134|31134|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Tue Jun  9 03:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7442** entries, **7442** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|25559|37202|7442|20.0%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|7126|24.3%|95.7%|
[firehol_level3](#firehol_level3)|107925|9625377|7083|0.0%|95.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|7075|7.6%|95.0%|
[blocklist_de](#blocklist_de)|31134|31134|1401|4.4%|18.8%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|1330|38.0%|17.8%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|1102|1.3%|14.8%|
[firehol_proxies](#firehol_proxies)|11678|11905|892|7.4%|11.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|532|0.0%|7.1%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|518|7.1%|6.9%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|400|4.1%|5.3%|
[et_tor](#et_tor)|6400|6400|356|5.5%|4.7%|
[dm_tor](#dm_tor)|6345|6345|352|5.5%|4.7%|
[bm_tor](#bm_tor)|6369|6369|351|5.5%|4.7%|
[proxyrss](#proxyrss)|1553|1553|349|22.4%|4.6%|
[xroxy](#xroxy)|2138|2138|287|13.4%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|212|0.0%|2.8%|
[proxz](#proxz)|1093|1093|192|17.5%|2.5%|
[php_commenters](#php_commenters)|385|385|160|41.5%|2.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|157|42.2%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|141|5.3%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|130|0.0%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|104|63.0%|1.3%|
[firehol_level1](#firehol_level1)|5091|688943669|79|0.0%|1.0%|
[et_block](#et_block)|999|18343755|79|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|78|0.0%|1.0%|
[nixspam](#nixspam)|29888|29888|78|0.2%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|63|0.3%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|55|0.2%|0.7%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|49|0.0%|0.6%|
[php_spammers](#php_spammers)|622|622|45|7.2%|0.6%|
[php_harvesters](#php_harvesters)|366|366|42|11.4%|0.5%|
[php_dictionary](#php_dictionary)|630|630|34|5.3%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|28|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|27|0.5%|0.3%|
[openbl_60d](#openbl_60d)|7199|7199|21|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|10|0.0%|0.1%|
[voipbl](#voipbl)|10507|10919|5|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[et_compromised](#et_compromised)|1678|1678|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1254|1254|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2874|2874|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|1|0.6%|0.0%|

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
[firehol_level3](#firehol_level3)|107925|9625377|92512|0.9%|100.0%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|29167|99.6%|31.5%|
[firehol_level2](#firehol_level2)|25559|37202|8414|22.6%|9.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|7075|95.0%|7.6%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|5899|7.1%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5744|0.0%|6.2%|
[firehol_proxies](#firehol_proxies)|11678|11905|5256|44.1%|5.6%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|3460|47.7%|3.7%|
[blocklist_de](#blocklist_de)|31134|31134|2698|8.6%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2475|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|2370|67.8%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1506|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|1499|56.8%|1.6%|
[xroxy](#xroxy)|2138|2138|1265|59.1%|1.3%|
[firehol_level1](#firehol_level1)|5091|688943669|1088|0.0%|1.1%|
[et_block](#et_block)|999|18343755|1011|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1008|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|815|8.4%|0.8%|
[proxyrss](#proxyrss)|1553|1553|778|50.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|719|0.0%|0.7%|
[et_tor](#et_tor)|6400|6400|659|10.2%|0.7%|
[proxz](#proxz)|1093|1093|657|60.1%|0.7%|
[bm_tor](#bm_tor)|6369|6369|635|9.9%|0.6%|
[dm_tor](#dm_tor)|6345|6345|634|9.9%|0.6%|
[php_commenters](#php_commenters)|385|385|289|75.0%|0.3%|
[nixspam](#nixspam)|29888|29888|241|0.8%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|238|1.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|233|62.6%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|210|1.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|198|0.1%|0.2%|
[php_spammers](#php_spammers)|622|622|131|21.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|124|75.1%|0.1%|
[php_dictionary](#php_dictionary)|630|630|119|18.8%|0.1%|
[php_harvesters](#php_harvesters)|366|366|81|22.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|78|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|64|1.2%|0.0%|
[openbl_60d](#openbl_60d)|7199|7199|52|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|48|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|35|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|18|2.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|15|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|13|0.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|13|0.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|11|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|6|3.8%|0.0%|
[shunlist](#shunlist)|1254|1254|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|2874|2874|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[openbl_7d](#openbl_7d)|824|824|3|0.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|2|0.9%|0.0%|
[zeus](#zeus)|233|233|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|391|391|1|0.2%|0.0%|

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
[firehol_level3](#firehol_level3)|107925|9625377|29168|0.3%|99.6%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|29167|31.5%|99.6%|
[firehol_level2](#firehol_level2)|25559|37202|8086|21.7%|27.6%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|7126|95.7%|24.3%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|2829|3.4%|9.6%|
[firehol_proxies](#firehol_proxies)|11678|11905|2424|20.3%|8.2%|
[blocklist_de](#blocklist_de)|31134|31134|2327|7.4%|7.9%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|2144|61.3%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1893|0.0%|6.4%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|1566|21.6%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|825|0.0%|2.8%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|668|6.9%|2.2%|
[xroxy](#xroxy)|2138|2138|648|30.3%|2.2%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|615|23.3%|2.1%|
[proxyrss](#proxyrss)|1553|1553|610|39.2%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|549|0.0%|1.8%|
[et_tor](#et_tor)|6400|6400|544|8.5%|1.8%|
[dm_tor](#dm_tor)|6345|6345|520|8.1%|1.7%|
[bm_tor](#bm_tor)|6369|6369|520|8.1%|1.7%|
[proxz](#proxz)|1093|1093|470|43.0%|1.6%|
[firehol_level1](#firehol_level1)|5091|688943669|316|0.0%|1.0%|
[et_block](#et_block)|999|18343755|308|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|307|0.0%|1.0%|
[php_commenters](#php_commenters)|385|385|215|55.8%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|192|51.6%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|157|0.0%|0.5%|
[nixspam](#nixspam)|29888|29888|136|0.4%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|132|0.6%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|129|0.7%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|114|69.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|98|0.0%|0.3%|
[php_spammers](#php_spammers)|622|622|77|12.3%|0.2%|
[php_dictionary](#php_dictionary)|630|630|77|12.2%|0.2%|
[php_harvesters](#php_harvesters)|366|366|61|16.6%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|44|0.8%|0.1%|
[openbl_60d](#openbl_60d)|7199|7199|25|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.0%|
[voipbl](#voipbl)|10507|10919|15|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|9|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|5|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|3|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|156|156|2|1.2%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|233|233|1|0.4%|0.0%|
[shunlist](#shunlist)|1254|1254|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2874|2874|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ciarmy](#ciarmy)|391|391|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Tue Jun  9 03:32:03 UTC 2015.

The ipset `virbl` has **14** entries, **14** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|107925|9625377|14|0.0%|100.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.1%|
[firehol_level1](#firehol_level1)|5091|688943669|1|0.0%|7.1%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Tue Jun  9 01:18:20 UTC 2015.

The ipset `voipbl` has **10507** entries, **10919** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1600|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|434|0.0%|3.9%|
[firehol_level1](#firehol_level1)|5091|688943669|334|0.0%|3.0%|
[fullbogons](#fullbogons)|3720|670264216|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|299|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|189|0.1%|1.7%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|78|0.0%|0.7%|
[firehol_level3](#firehol_level3)|107925|9625377|56|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|35|0.0%|0.3%|
[firehol_level2](#firehol_level2)|25559|37202|35|0.0%|0.3%|
[blocklist_de](#blocklist_de)|31134|31134|30|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|88|88|25|28.4%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|15|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|14|0.0%|0.1%|
[et_block](#et_block)|999|18343755|14|0.0%|0.1%|
[shunlist](#shunlist)|1254|1254|12|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7199|7199|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16150|16150|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|2874|2874|3|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6345|6345|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6369|6369|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|2|0.1%|0.0%|
[nixspam](#nixspam)|29888|29888|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11678|11905|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|391|391|1|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2890|2890|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Tue Jun  9 03:33:01 UTC 2015.

The ipset `xroxy` has **2138** entries, **2138** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11678|11905|2138|17.9%|100.0%|
[firehol_anonymous](#firehol_anonymous)|18197|82203|2138|2.6%|100.0%|
[firehol_level3](#firehol_level3)|107925|9625377|1279|0.0%|59.8%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|1265|1.3%|59.1%|
[ri_web_proxies](#ri_web_proxies)|7245|7245|934|12.8%|43.6%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|648|2.2%|30.3%|
[proxz](#proxz)|1093|1093|399|36.5%|18.6%|
[ri_connect_proxies](#ri_connect_proxies)|2637|2637|382|14.4%|17.8%|
[proxyrss](#proxyrss)|1553|1553|374|24.0%|17.4%|
[firehol_level2](#firehol_level2)|25559|37202|368|0.9%|17.2%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|287|3.8%|13.4%|
[blocklist_de](#blocklist_de)|31134|31134|207|0.6%|9.6%|
[blocklist_de_bots](#blocklist_de_bots)|3494|3494|167|4.7%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|105|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.8%|
[nixspam](#nixspam)|29888|29888|59|0.1%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|39|0.2%|1.8%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|38|0.3%|1.7%|
[php_dictionary](#php_dictionary)|630|630|38|6.0%|1.7%|
[php_spammers](#php_spammers)|622|622|30|4.8%|1.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[php_commenters](#php_commenters)|385|385|8|2.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|165|165|5|3.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|366|366|2|0.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_compromised](#et_compromised)|1678|1678|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6345|6345|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1718|1718|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6369|6369|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5242|5242|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  9 00:02:31 UTC 2015.

The ipset `zeus` has **233** entries, **233** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5091|688943669|233|0.0%|100.0%|
[et_block](#et_block)|999|18343755|229|0.0%|98.2%|
[firehol_level3](#firehol_level3)|107925|9625377|204|0.0%|87.5%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|87.1%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|202|2.0%|86.6%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|64|0.0%|27.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|2.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7199|7199|2|0.0%|0.8%|
[firehol_level2](#firehol_level2)|25559|37202|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|1|0.0%|0.4%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.4%|
[openbl_30d](#openbl_30d)|2874|2874|1|0.0%|0.4%|
[nixspam](#nixspam)|29888|29888|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|1|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|31134|31134|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Tue Jun  9 03:18:19 UTC 2015.

The ipset `zeus_badips` has **203** entries, **203** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|233|233|203|87.1%|100.0%|
[firehol_level1](#firehol_level1)|5091|688943669|203|0.0%|100.0%|
[et_block](#et_block)|999|18343755|203|0.0%|100.0%|
[firehol_level3](#firehol_level3)|107925|9625377|181|0.0%|89.1%|
[snort_ipfilter](#snort_ipfilter)|9624|9624|179|1.8%|88.1%|
[alienvault_reputation](#alienvault_reputation)|178836|178836|38|0.0%|18.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92512|92512|2|0.0%|0.9%|
[firehol_level2](#firehol_level2)|25559|37202|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29277|29277|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7442|7442|1|0.0%|0.4%|
[php_commenters](#php_commenters)|385|385|1|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7199|7199|1|0.0%|0.4%|
[nixspam](#nixspam)|29888|29888|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|19038|19038|1|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2125|2125|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|31134|31134|1|0.0%|0.4%|
