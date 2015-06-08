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

The following list was automatically generated on Mon Jun  8 00:37:03 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|176509 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|29751 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|16518 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3194 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|5186 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|482 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2376 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|17557 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|92 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|3028 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|158 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6476 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|1681 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|443 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|224 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6434 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1023 subnets, 18338662 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|0 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|2016 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
et_dshield|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
et_spamhaus|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|disabled|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6470 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|99 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[firehol_anonymous](#firehol_anonymous)|includes ipsets: firehol_proxies anonymous|ipv4 hash:net|11675 subnets, 75595 unique IPs|updated every 1 min  from [this link]()
[firehol_level1](#firehol_level1)|includes ipsets: feodo palevo sslbl zeus_badips dshield spamhaus_drop fullbogons|ipv4 hash:net|5010 subnets, 688456731 unique IPs|updated every 1 min  from [this link]()
[firehol_level2](#firehol_level2)|includes ipsets: zeus spamhaus_edrop openbl_7d blocklist_de virbl|ipv4 hash:net|19001 subnets, 517810 unique IPs|updated every 1 min  from [this link]()
[firehol_level3](#firehol_level3)|includes ipsets: openbl_30d stopforumspam_7d malc0de shunlist malwaredomainlist bruteforceblocker ib_bluetack_spyware ib_bluetack_spyware ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers|ipv4 hash:net|40636 subnets, 377754 unique IPs|updated every 1 min  from [this link]()
[firehol_proxies](#firehol_proxies)|includes ipsets: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy|ipv4 hash:net|11468 subnets, 11689 unique IPs|updated every 1 min  from [this link]()
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|39998 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
openbl_180d|[OpenBL.org](http://www.openbl.org/) last 180 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_180days.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|101 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3048 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
openbl_360d|[OpenBL.org](http://www.openbl.org/) last 360 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_360days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7239 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|815 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
openbl_all|[OpenBL.org](http://www.openbl.org/) last all IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_all.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|373 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|589 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|341 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|580 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1762 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1001 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2547 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|6963 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1206 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9408 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|652 subnets, 18338560 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 487424 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|381 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stopforumspam_180d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6250 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92247 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stopforumspam_365d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29870 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
stopforumspam_90d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
stopforumspam_ever|[StopForumSpam.com](http://www.stopforumspam.com) all IPs used by forum spammers, **ever** (normally you don't want to use this ipset, use the hourly one which includes last 24 hours IPs or the 7 days one)|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|0 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10491 subnets, 10902 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2119 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|234 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|203 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Sun Jun  7 22:00:44 UTC 2015.

The ipset `alienvault_reputation` has **176509** entries, **176509** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13869|0.0%|7.8%|
[openbl_60d](#openbl_60d)|7239|7239|7217|99.6%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6765|0.0%|3.8%|
[et_block](#et_block)|1023|18338662|5278|0.0%|2.9%|
[firehol_level1](#firehol_level1)|5010|688456731|5061|0.0%|2.8%|
[firehol_level3](#firehol_level3)|40636|377754|4227|1.1%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4119|0.0%|2.3%|
[dshield](#dshield)|20|5120|3843|75.0%|2.1%|
[openbl_30d](#openbl_30d)|3048|3048|3032|99.4%|1.7%|
[firehol_level2](#firehol_level2)|19001|517810|1715|0.3%|0.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1374|0.0%|0.7%|
[et_compromised](#et_compromised)|2016|2016|1319|65.4%|0.7%|
[blocklist_de](#blocklist_de)|29751|29751|1230|4.1%|0.6%|
[shunlist](#shunlist)|1206|1206|1200|99.5%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|1073|63.8%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|1023|33.7%|0.5%|
[openbl_7d](#openbl_7d)|815|815|808|99.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|443|443|437|98.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|288|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|198|0.2%|0.1%|
[voipbl](#voipbl)|10491|10902|196|1.7%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|122|0.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|116|1.2%|0.0%|
[openbl_1d](#openbl_1d)|101|101|99|98.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|95|0.3%|0.0%|
[sslbl](#sslbl)|381|381|64|16.7%|0.0%|
[zeus](#zeus)|234|234|63|26.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|62|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|49|0.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|43|1.8%|0.0%|
[nixspam](#nixspam)|39998|39998|40|0.1%|0.0%|
[et_tor](#et_tor)|6470|6470|40|0.6%|0.0%|
[dm_tor](#dm_tor)|6434|6434|39|0.6%|0.0%|
[bm_tor](#bm_tor)|6476|6476|39|0.6%|0.0%|
[zeus_badips](#zeus_badips)|203|203|37|18.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|36|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|36|22.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11468|11689|32|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|26|6.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|24|0.7%|0.0%|
[php_commenters](#php_commenters)|373|373|17|4.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|16|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|15|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|15|16.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|14|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|10|2.9%|0.0%|
[malc0de](#malc0de)|351|351|10|2.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|10|0.6%|0.0%|
[php_dictionary](#php_dictionary)|589|589|8|1.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|7|0.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|224|224|6|2.6%|0.0%|
[php_spammers](#php_spammers)|580|580|5|0.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|482|482|5|1.0%|0.0%|
[xroxy](#xroxy)|2119|2119|4|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|3|0.1%|0.0%|
[proxz](#proxz)|1001|1001|3|0.2%|0.0%|
[feodo](#feodo)|99|99|2|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Mon Jun  8 00:11:44 UTC 2015.

The ipset `blocklist_de` has **29751** entries, **29751** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|19001|517810|29751|5.7%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|17526|99.8%|58.9%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|16517|99.9%|55.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|5185|99.9%|17.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|3752|0.0%|12.6%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|3176|99.4%|10.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|3006|99.2%|10.1%|
[firehol_level3](#firehol_level3)|40636|377754|2930|0.7%|9.8%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2510|2.7%|8.4%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|2374|99.9%|7.9%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1923|6.4%|6.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1534|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1466|0.0%|4.9%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|1348|21.5%|4.5%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|1230|0.6%|4.1%|
[nixspam](#nixspam)|39998|39998|1184|2.9%|3.9%|
[openbl_60d](#openbl_60d)|7239|7239|946|13.0%|3.1%|
[openbl_30d](#openbl_30d)|3048|3048|740|24.2%|2.4%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|601|0.7%|2.0%|
[et_compromised](#et_compromised)|2016|2016|601|29.8%|2.0%|
[firehol_proxies](#firehol_proxies)|11468|11689|597|5.1%|2.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|575|34.2%|1.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|482|482|481|99.7%|1.6%|
[openbl_7d](#openbl_7d)|815|815|404|49.5%|1.3%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|390|5.6%|1.3%|
[shunlist](#shunlist)|1206|1206|354|29.3%|1.1%|
[proxyrss](#proxyrss)|1762|1762|265|15.0%|0.8%|
[firehol_level1](#firehol_level1)|5010|688456731|199|0.0%|0.6%|
[xroxy](#xroxy)|2119|2119|194|9.1%|0.6%|
[et_block](#et_block)|1023|18338662|187|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|176|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|158|100.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|135|1.4%|0.4%|
[proxz](#proxz)|1001|1001|133|13.2%|0.4%|
[php_commenters](#php_commenters)|373|373|91|24.3%|0.3%|
[dshield](#dshield)|20|5120|82|1.6%|0.2%|
[php_spammers](#php_spammers)|580|580|80|13.7%|0.2%|
[php_dictionary](#php_dictionary)|589|589|80|13.5%|0.2%|
[openbl_1d](#openbl_1d)|101|101|78|77.2%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|73|79.3%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|64|2.5%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|43|0.0%|0.1%|
[php_harvesters](#php_harvesters)|341|341|39|11.4%|0.1%|
[voipbl](#voipbl)|10491|10902|35|0.3%|0.1%|
[ciarmy](#ciarmy)|443|443|34|7.6%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|14|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|8|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6434|6434|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6476|6476|4|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|234|234|1|0.4%|0.0%|
[sslbl](#sslbl)|381|381|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Mon Jun  8 00:30:22 UTC 2015.

The ipset `blocklist_de_apache` has **16518** entries, **16518** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|19001|517810|16517|3.1%|99.9%|
[blocklist_de](#blocklist_de)|29751|29751|16517|55.5%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|11059|62.9%|66.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|5186|100.0%|31.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2488|0.0%|15.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1313|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1089|0.0%|6.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|197|0.2%|1.1%|
[firehol_level3](#firehol_level3)|40636|377754|158|0.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|122|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|115|0.3%|0.6%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|46|0.7%|0.2%|
[shunlist](#shunlist)|1206|1206|31|2.5%|0.1%|
[ciarmy](#ciarmy)|443|443|31|6.9%|0.1%|
[nixspam](#nixspam)|39998|39998|30|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|29|18.3%|0.1%|
[php_commenters](#php_commenters)|373|373|23|6.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|21|0.6%|0.1%|
[firehol_level1](#firehol_level1)|5010|688456731|13|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|10|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|9|0.0%|0.0%|
[dshield](#dshield)|20|5120|9|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|8|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|5|0.8%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|5|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|4|0.6%|0.0%|
[openbl_30d](#openbl_30d)|3048|3048|4|0.1%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6434|6434|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6476|6476|4|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11468|11689|3|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|3|0.0%|0.0%|
[xroxy](#xroxy)|2119|2119|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|2|0.0%|0.0%|
[proxz](#proxz)|1001|1001|2|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1762|1762|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Mon Jun  8 00:30:24 UTC 2015.

The ipset `blocklist_de_bots` has **3194** entries, **3194** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|19001|517810|3176|0.6%|99.4%|
[blocklist_de](#blocklist_de)|29751|29751|3176|10.6%|99.4%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2196|2.3%|68.7%|
[firehol_level3](#firehol_level3)|40636|377754|1772|0.4%|55.4%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1756|5.8%|54.9%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|1301|20.8%|40.7%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|509|0.6%|15.9%|
[firehol_proxies](#firehol_proxies)|11468|11689|505|4.3%|15.8%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|324|4.6%|10.1%|
[proxyrss](#proxyrss)|1762|1762|265|15.0%|8.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|201|0.0%|6.2%|
[xroxy](#xroxy)|2119|2119|152|7.1%|4.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|119|75.3%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|114|0.0%|3.5%|
[proxz](#proxz)|1001|1001|108|10.7%|3.3%|
[php_commenters](#php_commenters)|373|373|77|20.6%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|60|2.3%|1.8%|
[firehol_level1](#firehol_level1)|5010|688456731|42|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|41|0.0%|1.2%|
[et_block](#et_block)|1023|18338662|41|0.0%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|34|0.0%|1.0%|
[nixspam](#nixspam)|39998|39998|31|0.0%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|30|0.0%|0.9%|
[php_harvesters](#php_harvesters)|341|341|29|8.5%|0.9%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|24|0.0%|0.7%|
[php_spammers](#php_spammers)|580|580|23|3.9%|0.7%|
[php_dictionary](#php_dictionary)|589|589|22|3.7%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|21|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|21|0.1%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|19|0.2%|0.5%|
[openbl_60d](#openbl_60d)|7239|7239|10|0.1%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|3|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3048|3048|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Mon Jun  8 00:30:26 UTC 2015.

The ipset `blocklist_de_bruteforce` has **5186** entries, **5186** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|5186|31.3%|100.0%|
[firehol_level2](#firehol_level2)|19001|517810|5185|1.0%|99.9%|
[blocklist_de](#blocklist_de)|29751|29751|5185|17.4%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|392|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|58|0.0%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|47|0.0%|0.9%|
[firehol_level3](#firehol_level3)|40636|377754|35|0.0%|0.6%|
[nixspam](#nixspam)|39998|39998|30|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|27|0.0%|0.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|26|0.0%|0.5%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|16|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|9|0.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|8|0.0%|0.1%|
[php_commenters](#php_commenters)|373|373|6|1.6%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|6|3.7%|0.1%|
[php_spammers](#php_spammers)|580|580|5|0.8%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|4|0.6%|0.0%|
[firehol_level1](#firehol_level1)|5010|688456731|4|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[xroxy](#xroxy)|2119|2119|1|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|1|0.0%|0.0%|
[shunlist](#shunlist)|1206|1206|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|1|0.0%|0.0%|
[proxz](#proxz)|1001|1001|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11468|11689|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|1|0.0%|0.0%|
[ciarmy](#ciarmy)|443|443|1|0.2%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Mon Jun  8 00:30:23 UTC 2015.

The ipset `blocklist_de_ftp` has **482** entries, **482** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|19001|517810|481|0.0%|99.7%|
[blocklist_de](#blocklist_de)|29751|29751|481|1.6%|99.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|40|0.0%|8.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|14|0.0%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|12|0.0%|2.4%|
[firehol_level3](#firehol_level3)|40636|377754|10|0.0%|2.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|8|0.0%|1.6%|
[php_harvesters](#php_harvesters)|341|341|6|1.7%|1.2%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|5|0.0%|1.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|3|0.0%|0.6%|
[nixspam](#nixspam)|39998|39998|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|2|1.2%|0.4%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1|0.0%|0.2%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.2%|
[php_dictionary](#php_dictionary)|589|589|1|0.1%|0.2%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Mon Jun  8 00:14:45 UTC 2015.

The ipset `blocklist_de_imap` has **2376** entries, **2376** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|19001|517810|2374|0.4%|99.9%|
[blocklist_de](#blocklist_de)|29751|29751|2374|7.9%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|2361|13.4%|99.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|215|0.0%|9.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|47|0.0%|1.9%|
[firehol_level3](#firehol_level3)|40636|377754|45|0.0%|1.8%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|43|0.0%|1.8%|
[openbl_60d](#openbl_60d)|7239|7239|35|0.4%|1.4%|
[openbl_30d](#openbl_30d)|3048|3048|31|1.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|31|0.0%|1.3%|
[nixspam](#nixspam)|39998|39998|20|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5010|688456731|18|0.0%|0.7%|
[et_block](#et_block)|1023|18338662|17|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|13|0.0%|0.5%|
[et_compromised](#et_compromised)|2016|2016|12|0.5%|0.5%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|11|0.6%|0.4%|
[openbl_7d](#openbl_7d)|815|815|10|1.2%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|9|0.1%|0.3%|
[firehol_proxies](#firehol_proxies)|11468|11689|9|0.0%|0.3%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|9|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|8|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|8|0.0%|0.3%|
[shunlist](#shunlist)|1206|1206|2|0.1%|0.0%|
[php_dictionary](#php_dictionary)|589|589|2|0.3%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|234|234|1|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|101|101|1|0.9%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|443|443|1|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|1|0.0%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Mon Jun  8 00:30:21 UTC 2015.

The ipset `blocklist_de_mail` has **17557** entries, **17557** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|19001|517810|17526|3.3%|99.8%|
[blocklist_de](#blocklist_de)|29751|29751|17526|58.9%|99.8%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|11059|66.9%|62.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2616|0.0%|14.9%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|2361|99.3%|13.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1390|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|1164|0.0%|6.6%|
[nixspam](#nixspam)|39998|39998|1129|2.8%|6.4%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|244|0.2%|1.3%|
[firehol_level3](#firehol_level3)|40636|377754|229|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|138|0.4%|0.7%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|108|1.1%|0.6%|
[firehol_proxies](#firehol_proxies)|11468|11689|90|0.7%|0.5%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|90|0.1%|0.5%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|63|0.9%|0.3%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|62|0.0%|0.3%|
[php_dictionary](#php_dictionary)|589|589|53|8.9%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|50|0.8%|0.2%|
[php_spammers](#php_spammers)|580|580|50|8.6%|0.2%|
[openbl_60d](#openbl_60d)|7239|7239|46|0.6%|0.2%|
[openbl_30d](#openbl_30d)|3048|3048|41|1.3%|0.2%|
[xroxy](#xroxy)|2119|2119|40|1.8%|0.2%|
[firehol_level1](#firehol_level1)|5010|688456731|26|0.0%|0.1%|
[et_block](#et_block)|1023|18338662|24|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|23|0.0%|0.1%|
[proxz](#proxz)|1001|1001|23|2.2%|0.1%|
[php_commenters](#php_commenters)|373|373|22|5.8%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|22|13.9%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|21|0.6%|0.1%|
[openbl_7d](#openbl_7d)|815|815|14|1.7%|0.0%|
[et_compromised](#et_compromised)|2016|2016|14|0.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|14|0.8%|0.0%|
[shunlist](#shunlist)|1206|1206|4|0.3%|0.0%|
[php_harvesters](#php_harvesters)|341|341|4|1.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6434|6434|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6476|6476|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|234|234|1|0.4%|0.0%|
[proxyrss](#proxyrss)|1762|1762|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|101|101|1|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|443|443|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Mon Jun  8 00:14:46 UTC 2015.

The ipset `blocklist_de_sip` has **92** entries, **92** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|19001|517810|73|0.0%|79.3%|
[blocklist_de](#blocklist_de)|29751|29751|73|0.2%|79.3%|
[voipbl](#voipbl)|10491|10902|30|0.2%|32.6%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|15|0.0%|16.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|12|0.0%|13.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|6.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|6.5%|
[firehol_level3](#firehol_level3)|40636|377754|3|0.0%|3.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|2.1%|
[et_block](#et_block)|1023|18338662|2|0.0%|2.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|1.0%|
[shunlist](#shunlist)|1206|1206|1|0.0%|1.0%|
[firehol_level1](#firehol_level1)|5010|688456731|1|0.0%|1.0%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Mon Jun  8 00:30:18 UTC 2015.

The ipset `blocklist_de_ssh` has **3028** entries, **3028** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|19001|517810|3008|0.5%|99.3%|
[blocklist_de](#blocklist_de)|29751|29751|3006|10.1%|99.2%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|1023|0.5%|33.7%|
[openbl_60d](#openbl_60d)|7239|7239|892|12.3%|29.4%|
[firehol_level3](#firehol_level3)|40636|377754|857|0.2%|28.3%|
[openbl_30d](#openbl_30d)|3048|3048|699|22.9%|23.0%|
[et_compromised](#et_compromised)|2016|2016|588|29.1%|19.4%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|563|33.4%|18.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|473|0.0%|15.6%|
[openbl_7d](#openbl_7d)|815|815|390|47.8%|12.8%|
[shunlist](#shunlist)|1206|1206|318|26.3%|10.5%|
[firehol_level1](#firehol_level1)|5010|688456731|118|0.0%|3.8%|
[et_block](#et_block)|1023|18338662|111|0.0%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|110|0.0%|3.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|108|0.0%|3.5%|
[openbl_1d](#openbl_1d)|101|101|77|76.2%|2.5%|
[dshield](#dshield)|20|5120|70|1.3%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|64|0.0%|2.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|28|17.7%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|16|0.0%|0.5%|
[nixspam](#nixspam)|39998|39998|11|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|3|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[ciarmy](#ciarmy)|443|443|2|0.4%|0.0%|
[sslbl](#sslbl)|381|381|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Mon Jun  8 00:14:48 UTC 2015.

The ipset `blocklist_de_strongips` has **158** entries, **158** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|19001|517810|158|0.0%|100.0%|
[blocklist_de](#blocklist_de)|29751|29751|158|0.5%|100.0%|
[firehol_level3](#firehol_level3)|40636|377754|134|0.0%|84.8%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|119|3.7%|75.3%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|117|0.1%|74.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|105|0.3%|66.4%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|86|1.3%|54.4%|
[php_commenters](#php_commenters)|373|373|37|9.9%|23.4%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|36|0.0%|22.7%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|29|0.1%|18.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|28|0.9%|17.7%|
[openbl_60d](#openbl_60d)|7239|7239|25|0.3%|15.8%|
[openbl_7d](#openbl_7d)|815|815|24|2.9%|15.1%|
[openbl_30d](#openbl_30d)|3048|3048|24|0.7%|15.1%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|22|0.1%|13.9%|
[shunlist](#shunlist)|1206|1206|21|1.7%|13.2%|
[openbl_1d](#openbl_1d)|101|101|18|17.8%|11.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|15|0.0%|9.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7|0.0%|4.4%|
[et_block](#et_block)|1023|18338662|7|0.0%|4.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|3.7%|
[firehol_level1](#firehol_level1)|5010|688456731|6|0.0%|3.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|6|0.1%|3.7%|
[php_spammers](#php_spammers)|580|580|5|0.8%|3.1%|
[xroxy](#xroxy)|2119|2119|4|0.1%|2.5%|
[firehol_proxies](#firehol_proxies)|11468|11689|4|0.0%|2.5%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|4|0.0%|2.5%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|3|0.0%|1.8%|
[proxyrss](#proxyrss)|1762|1762|3|0.1%|1.8%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|1.2%|
[proxz](#proxz)|1001|1001|2|0.1%|1.2%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|1.2%|
[nixspam](#nixspam)|39998|39998|2|0.0%|1.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|482|482|2|0.4%|1.2%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1|0.0%|0.6%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.6%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|1|0.0%|0.6%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Mon Jun  8 00:18:02 UTC 2015.

The ipset `bm_tor` has **6476** entries, **6476** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6434|6434|6309|98.0%|97.4%|
[et_tor](#et_tor)|6470|6470|5599|86.5%|86.4%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1061|11.2%|16.3%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|644|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|619|0.0%|9.5%|
[firehol_level3](#firehol_level3)|40636|377754|510|0.1%|7.8%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|494|1.6%|7.6%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|347|5.5%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|184|0.0%|2.8%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|173|0.2%|2.6%|
[firehol_proxies](#firehol_proxies)|11468|11689|169|1.4%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|166|44.6%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|166|0.0%|2.5%|
[php_commenters](#php_commenters)|373|373|42|11.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|39|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7239|7239|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|341|341|7|2.0%|0.1%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[firehol_level2](#firehol_level2)|19001|517810|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29751|29751|4|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.0%|
[firehol_level1](#firehol_level1)|5010|688456731|3|0.0%|0.0%|
[nixspam](#nixspam)|39998|39998|2|0.0%|0.0%|
[xroxy](#xroxy)|2119|2119|1|0.0%|0.0%|
[shunlist](#shunlist)|1206|1206|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5010|688456731|592708608|86.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10491|10902|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|5|0.0%|0.0%|
[firehol_level3](#firehol_level3)|40636|377754|3|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[ciarmy](#ciarmy)|443|443|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Sun Jun  7 22:20:38 UTC 2015.

The ipset `bruteforceblocker` has **1681** entries, **1681** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|40636|377754|1681|0.4%|100.0%|
[et_compromised](#et_compromised)|2016|2016|1603|79.5%|95.3%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|1073|0.6%|63.8%|
[openbl_60d](#openbl_60d)|7239|7239|979|13.5%|58.2%|
[openbl_30d](#openbl_30d)|3048|3048|940|30.8%|55.9%|
[firehol_level2](#firehol_level2)|19001|517810|641|0.1%|38.1%|
[blocklist_de](#blocklist_de)|29751|29751|575|1.9%|34.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|563|18.5%|33.4%|
[shunlist](#shunlist)|1206|1206|400|33.1%|23.7%|
[openbl_7d](#openbl_7d)|815|815|313|38.4%|18.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|152|0.0%|9.0%|
[firehol_level1](#firehol_level1)|5010|688456731|109|0.0%|6.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|101|0.0%|6.0%|
[et_block](#et_block)|1023|18338662|101|0.0%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|85|0.0%|5.0%|
[dshield](#dshield)|20|5120|66|1.2%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|46|0.0%|2.7%|
[openbl_1d](#openbl_1d)|101|101|34|33.6%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|14|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|13|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|11|0.4%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|7|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.1%|
[firehol_proxies](#firehol_proxies)|11468|11689|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|3|0.0%|0.1%|
[voipbl](#voipbl)|10491|10902|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|2|0.0%|0.1%|
[proxz](#proxz)|1001|1001|2|0.1%|0.1%|
[nixspam](#nixspam)|39998|39998|2|0.0%|0.1%|
[xroxy](#xroxy)|2119|2119|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1762|1762|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.0%|
[ciarmy](#ciarmy)|443|443|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|1|0.6%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Sun Jun  7 22:15:15 UTC 2015.

The ipset `ciarmy` has **443** entries, **443** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|176509|176509|437|0.2%|98.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|83|0.0%|18.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|44|0.0%|9.9%|
[firehol_level3](#firehol_level3)|40636|377754|38|0.0%|8.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|8.1%|
[shunlist](#shunlist)|1206|1206|35|2.9%|7.9%|
[firehol_level2](#firehol_level2)|19001|517810|34|0.0%|7.6%|
[blocklist_de](#blocklist_de)|29751|29751|34|0.1%|7.6%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|31|0.1%|6.9%|
[et_block](#et_block)|1023|18338662|6|0.0%|1.3%|
[firehol_level1](#firehol_level1)|5010|688456731|5|0.0%|1.1%|
[voipbl](#voipbl)|10491|10902|4|0.0%|0.9%|
[dshield](#dshield)|20|5120|4|0.0%|0.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|2|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|1|0.0%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Sun Jun  7 20:09:46 UTC 2015.

The ipset `cleanmx_viruses` has **224** entries, **224** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|33|0.0%|14.7%|
[firehol_level3](#firehol_level3)|40636|377754|19|0.0%|8.4%|
[malc0de](#malc0de)|351|351|18|5.1%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|9|0.0%|4.0%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|6|0.0%|2.6%|
[firehol_level1](#firehol_level1)|5010|688456731|2|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.4%|
[dshield](#dshield)|20|5120|1|0.0%|0.4%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Mon Jun  8 00:36:04 UTC 2015.

The ipset `dm_tor` has **6434** entries, **6434** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6476|6476|6309|97.4%|98.0%|
[et_tor](#et_tor)|6470|6470|5612|86.7%|87.2%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1047|11.1%|16.2%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|645|0.6%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|622|0.0%|9.6%|
[firehol_level3](#firehol_level3)|40636|377754|511|0.1%|7.9%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|495|1.6%|7.6%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|346|5.5%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|185|0.0%|2.8%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|172|0.2%|2.6%|
[firehol_proxies](#firehol_proxies)|11468|11689|168|1.4%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|165|44.3%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|165|0.0%|2.5%|
[php_commenters](#php_commenters)|373|373|42|11.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|39|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7239|7239|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|341|341|7|2.0%|0.1%|
[firehol_level2](#firehol_level2)|19001|517810|5|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29751|29751|4|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.0%|
[firehol_level1](#firehol_level1)|5010|688456731|3|0.0%|0.0%|
[nixspam](#nixspam)|39998|39998|2|0.0%|0.0%|
[xroxy](#xroxy)|2119|2119|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1206|1206|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Sun Jun  7 23:56:49 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5010|688456731|5120|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|3843|2.1%|75.0%|
[et_block](#et_block)|1023|18338662|1280|0.0%|25.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|768|0.0%|15.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|512|0.0%|10.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|256|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7239|7239|129|1.7%|2.5%|
[firehol_level3](#firehol_level3)|40636|377754|116|0.0%|2.2%|
[openbl_30d](#openbl_30d)|3048|3048|108|3.5%|2.1%|
[shunlist](#shunlist)|1206|1206|93|7.7%|1.8%|
[firehol_level2](#firehol_level2)|19001|517810|88|0.0%|1.7%|
[blocklist_de](#blocklist_de)|29751|29751|82|0.2%|1.6%|
[et_compromised](#et_compromised)|2016|2016|76|3.7%|1.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|70|2.3%|1.3%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|66|3.9%|1.2%|
[openbl_7d](#openbl_7d)|815|815|14|1.7%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|9|0.0%|0.1%|
[ciarmy](#ciarmy)|443|443|4|0.9%|0.0%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[proxz](#proxz)|1001|1001|2|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|11468|11689|2|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1762|1762|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|101|101|1|0.9%|0.0%|
[malc0de](#malc0de)|351|351|1|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|224|224|1|0.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5010|688456731|18056227|2.6%|98.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|18054912|98.4%|98.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8598311|2.4%|46.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|38.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272276|0.2%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|195933|0.1%|1.0%|
[fullbogons](#fullbogons)|3720|670264216|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|5278|2.9%|0.0%|
[firehol_level3](#firehol_level3)|40636|377754|1545|0.4%|0.0%|
[dshield](#dshield)|20|5120|1280|25.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1040|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1008|1.0%|0.0%|
[firehol_level2](#firehol_level2)|19001|517810|926|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|315|3.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|308|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|250|3.4%|0.0%|
[zeus](#zeus)|234|234|224|95.7%|0.0%|
[zeus_badips](#zeus_badips)|203|203|200|98.5%|0.0%|
[blocklist_de](#blocklist_de)|29751|29751|187|0.6%|0.0%|
[openbl_30d](#openbl_30d)|3048|3048|130|4.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|111|3.6%|0.0%|
[shunlist](#shunlist)|1206|1206|108|8.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|101|6.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[feodo](#feodo)|99|99|94|94.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|74|1.1%|0.0%|
[nixspam](#nixspam)|39998|39998|71|0.1%|0.0%|
[openbl_7d](#openbl_7d)|815|815|45|5.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|41|1.2%|0.0%|
[sslbl](#sslbl)|381|381|35|9.1%|0.0%|
[php_commenters](#php_commenters)|373|373|29|7.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|24|0.1%|0.0%|
[voipbl](#voipbl)|10491|10902|18|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|17|0.7%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|10|0.0%|0.0%|
[openbl_1d](#openbl_1d)|101|101|9|8.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|7|4.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[ciarmy](#ciarmy)|443|443|6|1.3%|0.0%|
[php_dictionary](#php_dictionary)|589|589|5|0.8%|0.0%|
[malc0de](#malc0de)|351|351|5|1.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6434|6434|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6476|6476|5|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|4|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|3|0.5%|0.0%|
[firehol_proxies](#firehol_proxies)|11468|11689|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|2|2.1%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|224|224|1|0.4%|0.0%|

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
[firehol_level3](#firehol_level3)|40636|377754|1808|0.4%|89.6%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|1603|95.3%|79.5%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|1319|0.7%|65.4%|
[openbl_60d](#openbl_60d)|7239|7239|1218|16.8%|60.4%|
[openbl_30d](#openbl_30d)|3048|3048|1122|36.8%|55.6%|
[firehol_level2](#firehol_level2)|19001|517810|669|0.1%|33.1%|
[blocklist_de](#blocklist_de)|29751|29751|601|2.0%|29.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|588|19.4%|29.1%|
[shunlist](#shunlist)|1206|1206|423|35.0%|20.9%|
[openbl_7d](#openbl_7d)|815|815|337|41.3%|16.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|199|0.0%|9.8%|
[firehol_level1](#firehol_level1)|5010|688456731|117|0.0%|5.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|100|0.0%|4.9%|
[et_block](#et_block)|1023|18338662|100|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|97|0.0%|4.8%|
[dshield](#dshield)|20|5120|76|1.4%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|52|0.0%|2.5%|
[openbl_1d](#openbl_1d)|101|101|35|34.6%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|14|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|12|0.5%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|11|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|7|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11468|11689|3|0.0%|0.1%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|3|0.0%|0.1%|
[voipbl](#voipbl)|10491|10902|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|2|0.0%|0.0%|
[proxz](#proxz)|1001|1001|2|0.1%|0.0%|
[nixspam](#nixspam)|39998|39998|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|2|0.0%|0.0%|
[xroxy](#xroxy)|2119|2119|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1762|1762|1|0.0%|0.0%|
[ciarmy](#ciarmy)|443|443|1|0.2%|0.0%|

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
[dm_tor](#dm_tor)|6434|6434|5612|87.2%|86.7%|
[bm_tor](#bm_tor)|6476|6476|5599|86.4%|86.5%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1073|11.4%|16.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|660|0.7%|10.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|633|0.0%|9.7%|
[firehol_level3](#firehol_level3)|40636|377754|532|0.1%|8.2%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|516|1.7%|7.9%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|342|5.4%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|189|0.0%|2.9%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|177|0.2%|2.7%|
[firehol_proxies](#firehol_proxies)|11468|11689|173|1.4%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|168|45.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|168|0.0%|2.5%|
[php_commenters](#php_commenters)|373|373|43|11.5%|0.6%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|40|0.0%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|22|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7239|7239|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|341|341|7|2.0%|0.1%|
[php_spammers](#php_spammers)|580|580|6|1.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|5|0.8%|0.0%|
[firehol_level2](#firehol_level2)|19001|517810|4|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29751|29751|4|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[xroxy](#xroxy)|2119|2119|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[nixspam](#nixspam)|39998|39998|2|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5010|688456731|2|0.0%|0.0%|
[shunlist](#shunlist)|1206|1206|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  8 00:18:14 UTC 2015.

The ipset `feodo` has **99** entries, **99** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5010|688456731|99|0.0%|100.0%|
[et_block](#et_block)|1023|18338662|94|0.0%|94.9%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|79|0.8%|79.7%|
[sslbl](#sslbl)|381|381|36|9.4%|36.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11|0.0%|11.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|3|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|2|0.0%|2.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|1.0%|
[firehol_level3](#firehol_level3)|40636|377754|1|0.0%|1.0%|

## firehol_anonymous

includes ipsets: firehol_proxies anonymous

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_anonymous` has **11675** entries, **75595** unique IPs.

The following table shows the overlaps of `firehol_anonymous` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_anonymous`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_anonymous`.
- ` this % ` is the percentage **of this ipset (`firehol_anonymous`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11468|11689|11689|100.0%|15.4%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|6963|100.0%|9.2%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|5323|5.7%|7.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3255|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2690|0.0%|3.5%|
[firehol_level3](#firehol_level3)|40636|377754|2649|0.7%|3.5%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|2575|8.6%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|2547|100.0%|3.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2233|0.0%|2.9%|
[xroxy](#xroxy)|2119|2119|2119|100.0%|2.8%|
[proxyrss](#proxyrss)|1762|1762|1762|100.0%|2.3%|
[proxz](#proxz)|1001|1001|1001|100.0%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|893|14.2%|1.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|0.8%|
[firehol_level2](#firehol_level2)|19001|517810|601|0.1%|0.7%|
[blocklist_de](#blocklist_de)|29751|29751|601|2.0%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|509|15.9%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|242|2.5%|0.3%|
[et_tor](#et_tor)|6470|6470|177|2.7%|0.2%|
[bm_tor](#bm_tor)|6476|6476|173|2.6%|0.2%|
[dm_tor](#dm_tor)|6434|6434|172|2.6%|0.2%|
[nixspam](#nixspam)|39998|39998|97|0.2%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|90|0.5%|0.1%|
[voipbl](#voipbl)|10491|10902|75|0.6%|0.0%|
[php_dictionary](#php_dictionary)|589|589|74|12.5%|0.0%|
[php_commenters](#php_commenters)|373|373|65|17.4%|0.0%|
[php_spammers](#php_spammers)|580|580|62|10.6%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|36|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|20|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|16|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|11|3.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|10|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|9|0.3%|0.0%|
[firehol_level1](#firehol_level1)|5010|688456731|6|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|4|2.5%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|3|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[sslbl](#sslbl)|381|381|1|0.2%|0.0%|
[shunlist](#shunlist)|1206|1206|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3048|3048|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|1|0.0%|0.0%|

## firehol_level1

includes ipsets: feodo palevo sslbl zeus_badips dshield spamhaus_drop fullbogons

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:15:43 UTC 2015.

The ipset `firehol_level1` has **5010** entries, **688456731** unique IPs.

The following table shows the overlaps of `firehol_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level1`.
- ` this % ` is the percentage **of this ipset (`firehol_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3720|670264216|670264216|100.0%|97.3%|
[bogons](#bogons)|13|592708608|592708608|100.0%|86.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|18338560|100.0%|2.6%|
[et_block](#et_block)|1023|18338662|18056227|98.4%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8765993|2.5%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7497728|81.6%|1.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4366750|3.1%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2512524|0.3%|0.3%|
[dshield](#dshield)|20|5120|5120|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|5061|2.8%|0.0%|
[firehol_level3](#firehol_level3)|40636|377754|2567|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1930|0.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1020|1.1%|0.0%|
[firehol_level2](#firehol_level2)|19001|517810|921|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|517|0.1%|0.0%|
[sslbl](#sslbl)|381|381|381|100.0%|0.0%|
[voipbl](#voipbl)|10491|10902|336|3.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|314|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|301|4.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|275|2.9%|0.0%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|0.0%|
[zeus](#zeus)|234|234|203|86.7%|0.0%|
[blocklist_de](#blocklist_de)|29751|29751|199|0.6%|0.0%|
[shunlist](#shunlist)|1206|1206|178|14.7%|0.0%|
[openbl_30d](#openbl_30d)|3048|3048|165|5.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|118|3.8%|0.0%|
[et_compromised](#et_compromised)|2016|2016|117|5.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|109|6.4%|0.0%|
[feodo](#feodo)|99|99|99|100.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|80|1.2%|0.0%|
[nixspam](#nixspam)|39998|39998|71|0.1%|0.0%|
[openbl_7d](#openbl_7d)|815|815|50|6.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|42|1.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|39|2.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|38|2.9%|0.0%|
[php_commenters](#php_commenters)|373|373|30|8.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|26|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|18|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|18|0.7%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|13|0.0%|0.0%|
[openbl_1d](#openbl_1d)|101|101|9|8.9%|0.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|6|3.7%|0.0%|
[php_dictionary](#php_dictionary)|589|589|5|0.8%|0.0%|
[malc0de](#malc0de)|351|351|5|1.4%|0.0%|
[firehol_proxies](#firehol_proxies)|11468|11689|5|0.0%|0.0%|
[ciarmy](#ciarmy)|443|443|5|1.1%|0.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6434|6434|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6476|6476|3|0.0%|0.0%|
[proxz](#proxz)|1001|1001|2|0.1%|0.0%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|224|224|2|0.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1762|1762|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|1|1.0%|0.0%|

## firehol_level2

includes ipsets: zeus spamhaus_edrop openbl_7d blocklist_de virbl

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level2` has **19001** entries, **517810** unique IPs.

The following table shows the overlaps of `firehol_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level2`.
- ` this % ` is the percentage **of this ipset (`firehol_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|487424|100.0%|94.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|274620|0.1%|53.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|100406|0.0%|19.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|34703|0.0%|6.7%|
[blocklist_de](#blocklist_de)|29751|29751|29751|100.0%|5.7%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|17526|99.8%|3.3%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|16517|99.9%|3.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|5185|99.9%|1.0%|
[firehol_level3](#firehol_level3)|40636|377754|3358|0.8%|0.6%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|3176|99.4%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|3008|99.3%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2592|2.8%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|2374|99.9%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1933|6.4%|0.3%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|1715|0.9%|0.3%|
[openbl_60d](#openbl_60d)|7239|7239|1359|18.7%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|1351|21.6%|0.2%|
[nixspam](#nixspam)|39998|39998|1187|2.9%|0.2%|
[openbl_30d](#openbl_30d)|3048|3048|1153|37.8%|0.2%|
[et_block](#et_block)|1023|18338662|926|0.0%|0.1%|
[firehol_level1](#firehol_level1)|5010|688456731|921|0.0%|0.1%|
[openbl_7d](#openbl_7d)|815|815|815|100.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|706|0.0%|0.1%|
[et_compromised](#et_compromised)|2016|2016|669|33.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|641|38.1%|0.1%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|601|0.7%|0.1%|
[firehol_proxies](#firehol_proxies)|11468|11689|597|5.1%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|482|482|481|99.7%|0.0%|
[shunlist](#shunlist)|1206|1206|394|32.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|390|5.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|339|3.6%|0.0%|
[proxyrss](#proxyrss)|1762|1762|265|15.0%|0.0%|
[zeus](#zeus)|234|234|234|100.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|0.0%|
[xroxy](#xroxy)|2119|2119|194|9.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|158|100.0%|0.0%|
[proxz](#proxz)|1001|1001|133|13.2%|0.0%|
[openbl_1d](#openbl_1d)|101|101|101|100.0%|0.0%|
[php_commenters](#php_commenters)|373|373|98|26.2%|0.0%|
[dshield](#dshield)|20|5120|88|1.7%|0.0%|
[php_spammers](#php_spammers)|580|580|80|13.7%|0.0%|
[php_dictionary](#php_dictionary)|589|589|80|13.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|73|79.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|64|2.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|54|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|40|11.7%|0.0%|
[voipbl](#voipbl)|10491|10902|35|0.3%|0.0%|
[ciarmy](#ciarmy)|443|443|34|7.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|14|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|10|0.0%|0.0%|
[dm_tor](#dm_tor)|6434|6434|5|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6476|6476|4|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[sslbl](#sslbl)|381|381|1|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malc0de](#malc0de)|351|351|1|0.2%|0.0%|

## firehol_level3

includes ipsets: openbl_30d stopforumspam_7d malc0de shunlist malwaredomainlist bruteforceblocker ib_bluetack_spyware ib_bluetack_spyware ib_bluetack_webexploit php_commenters php_dictionary php_harvesters php_spammers

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_level3` has **40636** entries, **377754** unique IPs.

The following table shows the overlaps of `firehol_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_level3`.
- ` this % ` is the percentage **of this ipset (`firehol_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|339173|100.0%|89.7%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|30064|32.5%|7.9%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|29870|100.0%|7.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|14107|0.0%|3.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|11980|0.0%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9001|0.0%|2.3%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|4227|2.3%|1.1%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|3754|60.0%|0.9%|
[firehol_level2](#firehol_level2)|19001|517810|3358|0.6%|0.8%|
[openbl_60d](#openbl_60d)|7239|7239|3125|43.1%|0.8%|
[openbl_30d](#openbl_30d)|3048|3048|3048|100.0%|0.8%|
[blocklist_de](#blocklist_de)|29751|29751|2930|9.8%|0.7%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|2649|3.5%|0.7%|
[firehol_proxies](#firehol_proxies)|11468|11689|2595|22.2%|0.6%|
[firehol_level1](#firehol_level1)|5010|688456731|2567|0.0%|0.6%|
[et_compromised](#et_compromised)|2016|2016|1808|89.6%|0.4%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|1772|55.4%|0.4%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|1709|24.5%|0.4%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|1681|100.0%|0.4%|
[et_block](#et_block)|1023|18338662|1545|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1527|0.0%|0.4%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1450|100.0%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1288|100.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1240|0.0%|0.3%|
[shunlist](#shunlist)|1206|1206|1206|100.0%|0.3%|
[fullbogons](#fullbogons)|3720|670264216|931|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|857|28.3%|0.2%|
[openbl_7d](#openbl_7d)|815|815|815|100.0%|0.2%|
[xroxy](#xroxy)|2119|2119|721|34.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|692|7.3%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|646|25.3%|0.1%|
[proxyrss](#proxyrss)|1762|1762|601|34.1%|0.1%|
[php_dictionary](#php_dictionary)|589|589|589|100.0%|0.1%|
[php_spammers](#php_spammers)|580|580|580|100.0%|0.1%|
[et_tor](#et_tor)|6470|6470|532|8.2%|0.1%|
[dm_tor](#dm_tor)|6434|6434|511|7.9%|0.1%|
[bm_tor](#bm_tor)|6476|6476|510|7.8%|0.1%|
[proxz](#proxz)|1001|1001|462|46.1%|0.1%|
[php_commenters](#php_commenters)|373|373|373|100.0%|0.0%|
[malc0de](#malc0de)|351|351|351|100.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|341|100.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|229|1.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|189|50.8%|0.0%|
[nixspam](#nixspam)|39998|39998|185|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|158|0.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|134|84.8%|0.0%|
[dshield](#dshield)|20|5120|116|2.2%|0.0%|
[openbl_1d](#openbl_1d)|101|101|101|100.0%|0.0%|
[sslbl](#sslbl)|381|381|59|15.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|45|1.8%|0.0%|
[ciarmy](#ciarmy)|443|443|38|8.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|35|0.6%|0.0%|
[voipbl](#voipbl)|10491|10902|33|0.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|224|224|19|8.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|16|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|15|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|482|482|10|2.0%|0.0%|
[zeus](#zeus)|234|234|4|1.7%|0.0%|
[zeus_badips](#zeus_badips)|203|203|3|1.4%|0.0%|
[bogons](#bogons)|13|592708608|3|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|3|3.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[feodo](#feodo)|99|99|1|1.0%|0.0%|

## firehol_proxies

includes ipsets: ib_bluetack_proxies maxmind_proxy_fraud proxyrss proxz ri_connect_proxies ri_web_proxies xroxy

Source is downloaded from [this link]().

The last time downloaded was found to be dated: Sun Jun  7 22:20:34 UTC 2015.

The ipset `firehol_proxies` has **11468** entries, **11689** unique IPs.

The following table shows the overlaps of `firehol_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `firehol_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `firehol_proxies`.
- ` this % ` is the percentage **of this ipset (`firehol_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_anonymous](#firehol_anonymous)|11675|75595|11689|15.4%|100.0%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|6963|100.0%|59.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|5153|5.5%|44.0%|
[firehol_level3](#firehol_level3)|40636|377754|2595|0.6%|22.2%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|2547|100.0%|21.7%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|2522|8.4%|21.5%|
[xroxy](#xroxy)|2119|2119|2119|100.0%|18.1%|
[proxyrss](#proxyrss)|1762|1762|1762|100.0%|15.0%|
[proxz](#proxz)|1001|1001|1001|100.0%|8.5%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|886|14.1%|7.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|663|100.0%|5.6%|
[firehol_level2](#firehol_level2)|19001|517810|597|0.1%|5.1%|
[blocklist_de](#blocklist_de)|29751|29751|597|2.0%|5.1%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|505|15.8%|4.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|479|0.0%|4.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|372|100.0%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|357|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|268|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|240|2.5%|2.0%|
[et_tor](#et_tor)|6470|6470|173|2.6%|1.4%|
[bm_tor](#bm_tor)|6476|6476|169|2.6%|1.4%|
[dm_tor](#dm_tor)|6434|6434|168|2.6%|1.4%|
[nixspam](#nixspam)|39998|39998|96|0.2%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|90|0.5%|0.7%|
[php_dictionary](#php_dictionary)|589|589|74|12.5%|0.6%|
[php_commenters](#php_commenters)|373|373|64|17.1%|0.5%|
[php_spammers](#php_spammers)|580|580|62|10.6%|0.5%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|32|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7239|7239|18|0.2%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|16|0.0%|0.1%|
[php_harvesters](#php_harvesters)|341|341|11|3.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|10|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|9|0.3%|0.0%|
[firehol_level1](#firehol_level1)|5010|688456731|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|4|2.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.0%|
[et_compromised](#et_compromised)|2016|2016|3|0.1%|0.0%|
[et_block](#et_block)|1023|18338662|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|1|0.0%|0.0%|
[sslbl](#sslbl)|381|381|1|0.2%|0.0%|
[shunlist](#shunlist)|1206|1206|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5010|688456731|670264216|97.3%|100.0%|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|4235823|3.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565248|6.1%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|249087|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|239993|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|151552|0.8%|0.0%|
[et_block](#et_block)|1023|18338662|20480|0.1%|0.0%|
[firehol_level3](#firehol_level3)|40636|377754|931|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|890|0.2%|0.0%|
[voipbl](#voipbl)|10491|10902|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|13|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|9|0.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[ciarmy](#ciarmy)|443|443|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun Jun  7 05:00:59 UTC 2015.

The ipset `ib_bluetack_badpeers` has **47940** entries, **47940** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|394|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|226|0.0%|0.4%|
[firehol_level1](#firehol_level1)|5010|688456731|18|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11468|11689|16|0.1%|0.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|16|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|15|0.0%|0.0%|
[firehol_level3](#firehol_level3)|40636|377754|15|0.0%|0.0%|
[firehol_level2](#firehol_level2)|19001|517810|14|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29751|29751|14|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|14|0.0%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|13|0.0%|0.0%|
[nixspam](#nixspam)|39998|39998|11|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|11|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|9|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|8|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|0.0%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.0%|
[xroxy](#xroxy)|2119|2119|3|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|3|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|1|0.0%|0.0%|
[proxz](#proxz)|1001|1001|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1762|1762|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|1|0.0%|0.0%|

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
[firehol_level1](#firehol_level1)|5010|688456731|7497728|1.0%|81.6%|
[et_block](#et_block)|1023|18338662|7079936|38.6%|77.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6932480|37.8%|75.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3720|670264216|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|145472|0.1%|1.5%|
[firehol_level3](#firehol_level3)|40636|377754|1240|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|732|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|518|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|150|0.5%|0.0%|
[nixspam](#nixspam)|39998|39998|70|0.1%|0.0%|
[firehol_level2](#firehol_level2)|19001|517810|54|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29751|29751|43|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|34|1.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|33|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|17|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|12|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3048|3048|12|0.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[zeus](#zeus)|234|234|10|4.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|7|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|6|0.1%|0.0%|
[openbl_7d](#openbl_7d)|815|815|5|0.6%|0.0%|
[et_compromised](#et_compromised)|2016|2016|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|5|0.2%|0.0%|
[dm_tor](#dm_tor)|6434|6434|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6476|6476|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|4|0.0%|0.0%|
[shunlist](#shunlist)|1206|1206|3|0.2%|0.0%|
[php_spammers](#php_spammers)|580|580|3|0.5%|0.0%|
[php_dictionary](#php_dictionary)|589|589|3|0.5%|0.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|3|1.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11468|11689|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|2|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|101|101|1|0.9%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun Jun  7 09:27:01 UTC 2015.

The ipset `ib_bluetack_level1` has **218307** entries, **764993634** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|16302420|4.6%|2.1%|
[firehol_level1](#firehol_level1)|5010|688456731|2512524|0.3%|0.3%|
[et_block](#et_block)|1023|18338662|2272276|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2272265|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1354507|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3720|670264216|239993|0.0%|0.0%|
[firehol_level2](#firehol_level2)|19001|517810|34703|6.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|33155|6.8%|0.0%|
[firehol_level3](#firehol_level3)|40636|377754|14107|3.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|13247|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|4119|2.3%|0.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|3255|4.3%|0.0%|
[blocklist_de](#blocklist_de)|29751|29751|1534|5.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1511|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|1390|7.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|1313|7.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|559|1.8%|0.0%|
[nixspam](#nixspam)|39998|39998|450|1.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|394|0.8%|0.0%|
[voipbl](#voipbl)|10491|10902|299|2.7%|0.0%|
[firehol_proxies](#firehol_proxies)|11468|11689|268|2.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[et_tor](#et_tor)|6470|6470|168|2.5%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|167|2.3%|0.0%|
[bm_tor](#bm_tor)|6476|6476|166|2.5%|0.0%|
[dm_tor](#dm_tor)|6434|6434|165|2.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|136|1.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|130|2.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|79|3.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|76|0.8%|0.0%|
[openbl_30d](#openbl_30d)|3048|3048|67|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|66|5.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|64|2.1%|0.0%|
[xroxy](#xroxy)|2119|2119|58|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|56|8.4%|0.0%|
[et_compromised](#et_compromised)|2016|2016|52|2.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|46|2.7%|0.0%|
[proxz](#proxz)|1001|1001|36|3.5%|0.0%|
[ciarmy](#ciarmy)|443|443|36|8.1%|0.0%|
[proxyrss](#proxyrss)|1762|1762|34|1.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|31|1.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|30|0.9%|0.0%|
[shunlist](#shunlist)|1206|1206|28|2.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|26|0.5%|0.0%|
[openbl_7d](#openbl_7d)|815|815|18|2.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|482|482|14|2.9%|0.0%|
[php_harvesters](#php_harvesters)|341|341|11|3.2%|0.0%|
[php_dictionary](#php_dictionary)|589|589|11|1.8%|0.0%|
[malc0de](#malc0de)|351|351|11|3.1%|0.0%|
[php_commenters](#php_commenters)|373|373|9|2.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|224|224|9|4.0%|0.0%|
[php_spammers](#php_spammers)|580|580|8|1.3%|0.0%|
[zeus](#zeus)|234|234|6|2.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|6|6.5%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|4|1.9%|0.0%|
[sslbl](#sslbl)|381|381|3|0.7%|0.0%|
[feodo](#feodo)|99|99|3|3.0%|0.0%|
[openbl_1d](#openbl_1d)|101|101|1|0.9%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun Jun  7 05:30:38 UTC 2015.

The ipset `ib_bluetack_level2` has **72950** entries, **348710251** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|16302420|2.1%|4.6%|
[firehol_level1](#firehol_level1)|5010|688456731|8765993|1.2%|2.5%|
[et_block](#et_block)|1023|18338662|8598311|46.8%|2.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|8532506|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|2830203|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3720|670264216|249087|0.0%|0.0%|
[firehol_level2](#firehol_level2)|19001|517810|100406|19.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|98904|20.2%|0.0%|
[firehol_level3](#firehol_level3)|40636|377754|9001|2.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7728|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|6765|3.8%|0.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|2690|3.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2489|2.6%|0.0%|
[blocklist_de](#blocklist_de)|29751|29751|1466|4.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|1164|6.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|1089|6.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|882|2.9%|0.0%|
[dshield](#dshield)|20|5120|768|15.0%|0.0%|
[nixspam](#nixspam)|39998|39998|696|1.7%|0.0%|
[voipbl](#voipbl)|10491|10902|434|3.9%|0.0%|
[firehol_proxies](#firehol_proxies)|11468|11689|357|3.0%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|327|4.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|226|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|200|2.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|192|3.0%|0.0%|
[et_tor](#et_tor)|6470|6470|189|2.9%|0.0%|
[dm_tor](#dm_tor)|6434|6434|185|2.8%|0.0%|
[bm_tor](#bm_tor)|6476|6476|184|2.8%|0.0%|
[openbl_30d](#openbl_30d)|3048|3048|160|5.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|114|3.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|110|3.6%|0.0%|
[xroxy](#xroxy)|2119|2119|104|4.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|103|1.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|97|3.8%|0.0%|
[et_compromised](#et_compromised)|2016|2016|97|4.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|85|5.0%|0.0%|
[shunlist](#shunlist)|1206|1206|65|5.3%|0.0%|
[proxyrss](#proxyrss)|1762|1762|65|3.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|58|1.1%|0.0%|
[php_spammers](#php_spammers)|580|580|49|8.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|47|1.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|45|3.1%|0.0%|
[openbl_7d](#openbl_7d)|815|815|44|5.3%|0.0%|
[ciarmy](#ciarmy)|443|443|44|9.9%|0.0%|
[proxz](#proxz)|1001|1001|38|3.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|26|2.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|26|3.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[malc0de](#malc0de)|351|351|21|5.9%|0.0%|
[php_dictionary](#php_dictionary)|589|589|20|3.3%|0.0%|
[php_commenters](#php_commenters)|373|373|15|4.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|482|482|12|2.4%|0.0%|
[zeus](#zeus)|234|234|9|3.8%|0.0%|
[php_harvesters](#php_harvesters)|341|341|9|2.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|224|224|9|4.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|8|3.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|7|4.4%|0.0%|
[openbl_1d](#openbl_1d)|101|101|6|5.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|6|6.5%|0.0%|
[sslbl](#sslbl)|381|381|4|1.0%|0.0%|
[feodo](#feodo)|99|99|3|3.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun Jun  7 05:30:49 UTC 2015.

The ipset `ib_bluetack_level3` has **17812** entries, **139104927** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5010|688456731|4366750|0.6%|3.1%|
[fullbogons](#fullbogons)|3720|670264216|4235823|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2830203|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1354507|0.1%|0.9%|
[firehol_level2](#firehol_level2)|19001|517810|274620|53.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|270785|55.5%|0.1%|
[et_block](#et_block)|1023|18338662|195933|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|130368|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|13869|7.8%|0.0%|
[firehol_level3](#firehol_level3)|40636|377754|11980|3.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|9226|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|5743|6.2%|0.0%|
[blocklist_de](#blocklist_de)|29751|29751|3752|12.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|2616|14.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|2488|15.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|2233|2.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1948|6.5%|0.0%|
[voipbl](#voipbl)|10491|10902|1600|14.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1172|2.4%|0.0%|
[nixspam](#nixspam)|39998|39998|1071|2.6%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|740|10.2%|0.0%|
[et_tor](#et_tor)|6470|6470|633|9.7%|0.0%|
[dm_tor](#dm_tor)|6434|6434|622|9.6%|0.0%|
[bm_tor](#bm_tor)|6476|6476|619|9.5%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11468|11689|479|4.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|473|15.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|461|7.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|392|7.5%|0.0%|
[openbl_30d](#openbl_30d)|3048|3048|304|9.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|236|2.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|215|9.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|201|6.2%|0.0%|
[et_compromised](#et_compromised)|2016|2016|199|9.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|198|2.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|152|9.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|147|11.4%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[openbl_7d](#openbl_7d)|815|815|110|13.4%|0.0%|
[shunlist](#shunlist)|1206|1206|108|8.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|108|7.4%|0.0%|
[xroxy](#xroxy)|2119|2119|99|4.6%|0.0%|
[proxz](#proxz)|1001|1001|83|8.2%|0.0%|
[ciarmy](#ciarmy)|443|443|83|18.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|54|2.1%|0.0%|
[proxyrss](#proxyrss)|1762|1762|53|3.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|51|7.6%|0.0%|
[malc0de](#malc0de)|351|351|48|13.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|482|482|40|8.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|224|224|33|14.7%|0.0%|
[php_spammers](#php_spammers)|580|580|32|5.5%|0.0%|
[php_dictionary](#php_dictionary)|589|589|31|5.2%|0.0%|
[sslbl](#sslbl)|381|381|29|7.6%|0.0%|
[php_commenters](#php_commenters)|373|373|24|6.4%|0.0%|
[php_harvesters](#php_harvesters)|341|341|18|5.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|15|9.4%|0.0%|
[zeus](#zeus)|234|234|13|5.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|12|13.0%|0.0%|
[feodo](#feodo)|99|99|11|11.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|10|4.9%|0.0%|
[openbl_1d](#openbl_1d)|101|101|7|6.9%|0.0%|
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
[firehol_proxies](#firehol_proxies)|11468|11689|663|5.6%|100.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|663|0.8%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|56|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|51|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|3.9%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|20|0.0%|3.0%|
[firehol_level3](#firehol_level3)|40636|377754|15|0.0%|2.2%|
[xroxy](#xroxy)|2119|2119|13|0.6%|1.9%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|13|0.1%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|12|0.0%|1.8%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|7|0.2%|1.0%|
[proxz](#proxz)|1001|1001|6|0.5%|0.9%|
[proxyrss](#proxyrss)|1762|1762|6|0.3%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|5|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.3%|
[nixspam](#nixspam)|39998|39998|2|0.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[firehol_level2](#firehol_level2)|19001|517810|2|0.0%|0.3%|
[firehol_level1](#firehol_level1)|5010|688456731|2|0.0%|0.3%|
[et_block](#et_block)|1023|18338662|2|0.0%|0.3%|
[blocklist_de](#blocklist_de)|29751|29751|2|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|589|589|1|0.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|1|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|1|0.0%|0.1%|

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
[firehol_level3](#firehol_level3)|40636|377754|339173|89.7%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|13247|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|9226|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|7728|0.0%|2.2%|
[firehol_level1](#firehol_level1)|5010|688456731|1930|0.0%|0.5%|
[et_block](#et_block)|1023|18338662|1040|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3720|670264216|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|46|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|27|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|25|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6434|6434|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6476|6476|22|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|15|0.1%|0.0%|
[firehol_proxies](#firehol_proxies)|11468|11689|10|0.0%|0.0%|
[firehol_level2](#firehol_level2)|19001|517810|10|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|10|0.0%|0.0%|
[nixspam](#nixspam)|39998|39998|8|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29751|29751|8|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|7|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10491|10902|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3048|3048|4|0.1%|0.0%|
[malc0de](#malc0de)|351|351|3|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|2|2.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|234|234|1|0.4%|0.0%|
[xroxy](#xroxy)|2119|2119|1|0.0%|0.0%|
[sslbl](#sslbl)|381|381|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[shunlist](#shunlist)|1206|1206|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[php_dictionary](#php_dictionary)|589|589|1|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[feodo](#feodo)|99|99|1|1.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|224|224|1|0.4%|0.0%|
[ciarmy](#ciarmy)|443|443|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|40636|377754|1450|0.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|45|0.0%|3.1%|
[firehol_level1](#firehol_level1)|5010|688456731|39|0.0%|2.6%|
[fullbogons](#fullbogons)|3720|670264216|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|10|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.4%|
[et_block](#et_block)|1023|18338662|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|3|0.2%|0.2%|
[firehol_proxies](#firehol_proxies)|11468|11689|3|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7239|7239|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3048|3048|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.1%|
[firehol_level2](#firehol_level2)|19001|517810|2|0.0%|0.1%|
[blocklist_de](#blocklist_de)|29751|29751|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|815|815|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|1|0.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|40636|377754|351|0.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|48|0.0%|13.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|5.9%|
[cleanmx_viruses](#cleanmx_viruses)|224|224|18|8.0%|5.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.1%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|10|0.0%|2.8%|
[firehol_level1](#firehol_level1)|5010|688456731|5|0.0%|1.4%|
[et_block](#et_block)|1023|18338662|5|0.0%|1.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|1.1%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|1.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|3|0.0%|0.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[firehol_level2](#firehol_level2)|19001|517810|1|0.0%|0.2%|
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
[firehol_level3](#firehol_level3)|40636|377754|1288|0.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|147|0.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|66|0.0%|5.1%|
[firehol_level1](#firehol_level1)|5010|688456731|38|0.0%|2.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|29|0.0%|2.2%|
[et_block](#et_block)|1023|18338662|29|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|28|0.2%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|27|0.0%|2.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3720|670264216|9|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|7|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|4|0.0%|0.3%|
[malc0de](#malc0de)|351|351|4|1.1%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Mon Jun  8 00:18:16 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11468|11689|372|3.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|372|0.4%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|232|0.2%|62.3%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|189|0.6%|50.8%|
[firehol_level3](#firehol_level3)|40636|377754|189|0.0%|50.8%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|174|1.8%|46.7%|
[et_tor](#et_tor)|6470|6470|168|2.5%|45.1%|
[bm_tor](#bm_tor)|6476|6476|166|2.5%|44.6%|
[dm_tor](#dm_tor)|6434|6434|165|2.5%|44.3%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|151|2.4%|40.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|125|0.0%|33.6%|
[php_commenters](#php_commenters)|373|373|39|10.4%|10.4%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|26|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7239|7239|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|341|341|6|1.7%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|4|0.0%|1.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|1.0%|
[php_dictionary](#php_dictionary)|589|589|4|0.6%|1.0%|
[xroxy](#xroxy)|2119|2119|1|0.0%|0.2%|
[voipbl](#voipbl)|10491|10902|1|0.0%|0.2%|
[shunlist](#shunlist)|1206|1206|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|1|0.0%|0.2%|
[nixspam](#nixspam)|39998|39998|1|0.0%|0.2%|
[firehol_level2](#firehol_level2)|19001|517810|1|0.0%|0.2%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|29751|29751|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Mon Jun  8 00:30:03 UTC 2015.

The ipset `nixspam` has **39998** entries, **39998** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|19001|517810|1187|0.2%|2.9%|
[blocklist_de](#blocklist_de)|29751|29751|1184|3.9%|2.9%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|1129|6.4%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1071|0.0%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|696|0.0%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|450|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|307|3.2%|0.7%|
[firehol_level3](#firehol_level3)|40636|377754|185|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|174|0.1%|0.4%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|97|0.1%|0.2%|
[firehol_proxies](#firehol_proxies)|11468|11689|96|0.8%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|92|0.3%|0.2%|
[php_dictionary](#php_dictionary)|589|589|82|13.9%|0.2%|
[firehol_level1](#firehol_level1)|5010|688456731|71|0.0%|0.1%|
[et_block](#et_block)|1023|18338662|71|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|70|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|70|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|70|0.0%|0.1%|
[php_spammers](#php_spammers)|580|580|65|11.2%|0.1%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|40|0.0%|0.1%|
[xroxy](#xroxy)|2119|2119|38|1.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|38|0.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|31|0.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|30|0.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|30|0.1%|0.0%|
[proxz](#proxz)|1001|1001|26|2.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|20|0.8%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|14|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|11|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|11|0.3%|0.0%|
[php_commenters](#php_commenters)|373|373|9|2.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|8|0.3%|0.0%|
[proxyrss](#proxyrss)|1762|1762|8|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|8|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|6|1.7%|0.0%|
[openbl_30d](#openbl_30d)|3048|3048|3|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6434|6434|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|2|0.1%|0.0%|
[bm_tor](#bm_tor)|6476|6476|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|2|1.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|482|482|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|234|234|1|0.4%|0.0%|
[shunlist](#shunlist)|1206|1206|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|815|815|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Mon Jun  8 00:07:00 UTC 2015.

The ipset `openbl_1d` has **101** entries, **101** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_7d](#openbl_7d)|815|815|101|12.3%|100.0%|
[openbl_60d](#openbl_60d)|7239|7239|101|1.3%|100.0%|
[openbl_30d](#openbl_30d)|3048|3048|101|3.3%|100.0%|
[firehol_level3](#firehol_level3)|40636|377754|101|0.0%|100.0%|
[firehol_level2](#firehol_level2)|19001|517810|101|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|99|0.0%|98.0%|
[blocklist_de](#blocklist_de)|29751|29751|78|0.2%|77.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|77|2.5%|76.2%|
[shunlist](#shunlist)|1206|1206|47|3.8%|46.5%|
[et_compromised](#et_compromised)|2016|2016|35|1.7%|34.6%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|34|2.0%|33.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|18|11.3%|17.8%|
[firehol_level1](#firehol_level1)|5010|688456731|9|0.0%|8.9%|
[et_block](#et_block)|1023|18338662|9|0.0%|8.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|8|0.0%|7.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|7|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|6|0.0%|5.9%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1|0.0%|0.9%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.9%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1|0.0%|0.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.9%|
[dshield](#dshield)|20|5120|1|0.0%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|1|0.0%|0.9%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|1|0.0%|0.9%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Mon Jun  8 00:07:00 UTC 2015.

The ipset `openbl_30d` has **3048** entries, **3048** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7239|7239|3048|42.1%|100.0%|
[firehol_level3](#firehol_level3)|40636|377754|3048|0.8%|100.0%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|3032|1.7%|99.4%|
[firehol_level2](#firehol_level2)|19001|517810|1153|0.2%|37.8%|
[et_compromised](#et_compromised)|2016|2016|1122|55.6%|36.8%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|940|55.9%|30.8%|
[openbl_7d](#openbl_7d)|815|815|815|100.0%|26.7%|
[blocklist_de](#blocklist_de)|29751|29751|740|2.4%|24.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|699|23.0%|22.9%|
[shunlist](#shunlist)|1206|1206|508|42.1%|16.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|304|0.0%|9.9%|
[firehol_level1](#firehol_level1)|5010|688456731|165|0.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|160|0.0%|5.2%|
[et_block](#et_block)|1023|18338662|130|0.0%|4.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|124|0.0%|4.0%|
[dshield](#dshield)|20|5120|108|2.1%|3.5%|
[openbl_1d](#openbl_1d)|101|101|101|100.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|67|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|41|0.2%|1.3%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|31|1.3%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|24|15.1%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|4|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|4|0.0%|0.1%|
[voipbl](#voipbl)|10491|10902|3|0.0%|0.0%|
[nixspam](#nixspam)|39998|39998|3|0.0%|0.0%|
[zeus](#zeus)|234|234|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Mon Jun  8 00:07:00 UTC 2015.

The ipset `openbl_60d` has **7239** entries, **7239** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|176509|176509|7217|4.0%|99.6%|
[firehol_level3](#firehol_level3)|40636|377754|3125|0.8%|43.1%|
[openbl_30d](#openbl_30d)|3048|3048|3048|100.0%|42.1%|
[firehol_level2](#firehol_level2)|19001|517810|1359|0.2%|18.7%|
[et_compromised](#et_compromised)|2016|2016|1218|60.4%|16.8%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|979|58.2%|13.5%|
[blocklist_de](#blocklist_de)|29751|29751|946|3.1%|13.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|892|29.4%|12.3%|
[openbl_7d](#openbl_7d)|815|815|815|100.0%|11.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|740|0.0%|10.2%|
[shunlist](#shunlist)|1206|1206|526|43.6%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|327|0.0%|4.5%|
[firehol_level1](#firehol_level1)|5010|688456731|301|0.0%|4.1%|
[et_block](#et_block)|1023|18338662|250|0.0%|3.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|239|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|167|0.0%|2.3%|
[dshield](#dshield)|20|5120|129|2.5%|1.7%|
[openbl_1d](#openbl_1d)|101|101|101|100.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|54|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|46|0.2%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|35|1.4%|0.4%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|26|0.2%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|25|15.8%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|24|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|21|0.3%|0.2%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|20|0.0%|0.2%|
[et_tor](#et_tor)|6470|6470|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6434|6434|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6476|6476|20|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[firehol_proxies](#firehol_proxies)|11468|11689|18|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|17|0.0%|0.2%|
[nixspam](#nixspam)|39998|39998|14|0.0%|0.1%|
[php_commenters](#php_commenters)|373|373|10|2.6%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|10|0.3%|0.1%|
[voipbl](#voipbl)|10491|10902|8|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|5|0.0%|0.0%|
[zeus](#zeus)|234|234|2|0.8%|0.0%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Mon Jun  8 00:07:00 UTC 2015.

The ipset `openbl_7d` has **815** entries, **815** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7239|7239|815|11.2%|100.0%|
[openbl_30d](#openbl_30d)|3048|3048|815|26.7%|100.0%|
[firehol_level3](#firehol_level3)|40636|377754|815|0.2%|100.0%|
[firehol_level2](#firehol_level2)|19001|517810|815|0.1%|100.0%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|808|0.4%|99.1%|
[blocklist_de](#blocklist_de)|29751|29751|404|1.3%|49.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|390|12.8%|47.8%|
[et_compromised](#et_compromised)|2016|2016|337|16.7%|41.3%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|313|18.6%|38.4%|
[shunlist](#shunlist)|1206|1206|216|17.9%|26.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|110|0.0%|13.4%|
[openbl_1d](#openbl_1d)|101|101|101|100.0%|12.3%|
[firehol_level1](#firehol_level1)|5010|688456731|50|0.0%|6.1%|
[et_block](#et_block)|1023|18338662|45|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|44|0.0%|5.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|42|0.0%|5.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|24|15.1%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|18|0.0%|2.2%|
[dshield](#dshield)|20|5120|14|0.2%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|14|0.0%|1.7%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|10|0.4%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|3|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1|0.0%|0.1%|
[php_spammers](#php_spammers)|580|580|1|0.1%|0.1%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.1%|
[nixspam](#nixspam)|39998|39998|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  8 00:18:11 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5010|688456731|13|0.0%|100.0%|
[et_block](#et_block)|1023|18338662|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1|0.0%|7.6%|
[firehol_level3](#firehol_level3)|40636|377754|1|0.0%|7.6%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Mon Jun  8 00:00:39 UTC 2015.

The ipset `php_commenters` has **373** entries, **373** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|40636|377754|373|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|277|0.3%|74.2%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|202|0.6%|54.1%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|146|2.3%|39.1%|
[firehol_level2](#firehol_level2)|19001|517810|98|0.0%|26.2%|
[blocklist_de](#blocklist_de)|29751|29751|91|0.3%|24.3%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|77|2.4%|20.6%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|65|0.0%|17.4%|
[firehol_proxies](#firehol_proxies)|11468|11689|64|0.5%|17.1%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|51|0.5%|13.6%|
[et_tor](#et_tor)|6470|6470|43|0.6%|11.5%|
[dm_tor](#dm_tor)|6434|6434|42|0.6%|11.2%|
[bm_tor](#bm_tor)|6476|6476|42|0.6%|11.2%|
[php_spammers](#php_spammers)|580|580|40|6.8%|10.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|39|10.4%|10.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|37|23.4%|9.9%|
[firehol_level1](#firehol_level1)|5010|688456731|30|0.0%|8.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|29|0.0%|7.7%|
[et_block](#et_block)|1023|18338662|29|0.0%|7.7%|
[php_dictionary](#php_dictionary)|589|589|25|4.2%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|24|0.0%|6.4%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|23|0.3%|6.1%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|23|0.1%|6.1%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|22|0.1%|5.8%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|341|341|15|4.3%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|15|0.0%|4.0%|
[openbl_60d](#openbl_60d)|7239|7239|10|0.1%|2.6%|
[nixspam](#nixspam)|39998|39998|9|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|9|0.0%|2.4%|
[xroxy](#xroxy)|2119|2119|8|0.3%|2.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|7|0.0%|1.8%|
[proxz](#proxz)|1001|1001|7|0.6%|1.8%|
[proxyrss](#proxyrss)|1762|1762|7|0.3%|1.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|6|0.1%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|5|0.1%|1.3%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.2%|
[zeus](#zeus)|234|234|1|0.4%|0.2%|
[openbl_7d](#openbl_7d)|815|815|1|0.1%|0.2%|
[openbl_30d](#openbl_30d)|3048|3048|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|101|101|1|0.9%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|1|0.0%|0.2%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Mon Jun  8 00:00:44 UTC 2015.

The ipset `php_dictionary` has **589** entries, **589** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|40636|377754|589|0.1%|100.0%|
[php_spammers](#php_spammers)|580|580|211|36.3%|35.8%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|111|0.1%|18.8%|
[nixspam](#nixspam)|39998|39998|82|0.2%|13.9%|
[firehol_level2](#firehol_level2)|19001|517810|80|0.0%|13.5%|
[blocklist_de](#blocklist_de)|29751|29751|80|0.2%|13.5%|
[firehol_proxies](#firehol_proxies)|11468|11689|74|0.6%|12.5%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|74|0.0%|12.5%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|71|0.2%|12.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|66|0.7%|11.2%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|53|0.3%|8.9%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|47|0.6%|7.9%|
[xroxy](#xroxy)|2119|2119|35|1.6%|5.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|31|0.0%|5.2%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|25|0.4%|4.2%|
[php_commenters](#php_commenters)|373|373|25|6.7%|4.2%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|22|0.6%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|20|0.0%|3.3%|
[proxz](#proxz)|1001|1001|17|1.6%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|1.8%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|8|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|0.8%|
[firehol_level1](#firehol_level1)|5010|688456731|5|0.0%|0.8%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.8%|
[et_block](#et_block)|1023|18338662|5|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|4|0.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|4|0.0%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|4|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.5%|
[dm_tor](#dm_tor)|6434|6434|3|0.0%|0.5%|
[bm_tor](#bm_tor)|6476|6476|3|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|3|1.8%|0.5%|
[proxyrss](#proxyrss)|1762|1762|2|0.1%|0.3%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|2|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|482|482|1|0.2%|0.1%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Mon Jun  8 00:00:25 UTC 2015.

The ipset `php_harvesters` has **341** entries, **341** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|40636|377754|341|0.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|78|0.0%|22.8%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|58|0.1%|17.0%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|41|0.6%|12.0%|
[firehol_level2](#firehol_level2)|19001|517810|40|0.0%|11.7%|
[blocklist_de](#blocklist_de)|29751|29751|39|0.1%|11.4%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|29|0.9%|8.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|18|0.0%|5.2%|
[php_commenters](#php_commenters)|373|373|15|4.0%|4.3%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|11|0.1%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|11|0.0%|3.2%|
[firehol_proxies](#firehol_proxies)|11468|11689|11|0.0%|3.2%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|11|0.0%|3.2%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|10|0.0%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|2.6%|
[et_tor](#et_tor)|6470|6470|7|0.1%|2.0%|
[dm_tor](#dm_tor)|6434|6434|7|0.1%|2.0%|
[bm_tor](#bm_tor)|6476|6476|7|0.1%|2.0%|
[nixspam](#nixspam)|39998|39998|6|0.0%|1.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|1.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|482|482|6|1.2%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|4|0.0%|1.1%|
[xroxy](#xroxy)|2119|2119|2|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|2|0.0%|0.5%|
[proxyrss](#proxyrss)|1762|1762|2|0.1%|0.5%|
[php_spammers](#php_spammers)|580|580|2|0.3%|0.5%|
[php_dictionary](#php_dictionary)|589|589|2|0.3%|0.5%|
[openbl_60d](#openbl_60d)|7239|7239|2|0.0%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.5%|
[firehol_level1](#firehol_level1)|5010|688456731|2|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|2|1.2%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|1|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[fullbogons](#fullbogons)|3720|670264216|1|0.0%|0.2%|
[et_block](#et_block)|1023|18338662|1|0.0%|0.2%|
[bogons](#bogons)|13|592708608|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|1|0.0%|0.2%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Mon Jun  8 00:00:32 UTC 2015.

The ipset `php_spammers` has **580** entries, **580** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|40636|377754|580|0.1%|100.0%|
[php_dictionary](#php_dictionary)|589|589|211|35.8%|36.3%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|122|0.1%|21.0%|
[firehol_level2](#firehol_level2)|19001|517810|80|0.0%|13.7%|
[blocklist_de](#blocklist_de)|29751|29751|80|0.2%|13.7%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|66|0.2%|11.3%|
[nixspam](#nixspam)|39998|39998|65|0.1%|11.2%|
[firehol_proxies](#firehol_proxies)|11468|11689|62|0.5%|10.6%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|62|0.0%|10.6%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|61|0.6%|10.5%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|50|0.2%|8.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|49|0.0%|8.4%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|42|0.6%|7.2%|
[php_commenters](#php_commenters)|373|373|40|10.7%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|32|0.0%|5.5%|
[xroxy](#xroxy)|2119|2119|27|1.2%|4.6%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|26|0.4%|4.4%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|23|0.7%|3.9%|
[proxz](#proxz)|1001|1001|18|1.7%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|8|0.0%|1.3%|
[et_tor](#et_tor)|6470|6470|6|0.0%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|5|3.1%|0.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|5|0.0%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|5|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|5|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.6%|
[proxyrss](#proxyrss)|1762|1762|4|0.2%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.6%|
[firehol_level1](#firehol_level1)|5010|688456731|4|0.0%|0.6%|
[dm_tor](#dm_tor)|6434|6434|4|0.0%|0.6%|
[bm_tor](#bm_tor)|6476|6476|4|0.0%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|3|0.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.5%|
[et_block](#et_block)|1023|18338662|3|0.0%|0.5%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.3%|
[openbl_7d](#openbl_7d)|815|815|1|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7239|7239|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3048|3048|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|101|101|1|0.9%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|1|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|1|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|482|482|1|0.2%|0.1%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Sun Jun  7 21:51:26 UTC 2015.

The ipset `proxyrss` has **1762** entries, **1762** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11468|11689|1762|15.0%|100.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|1762|2.3%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|853|0.9%|48.4%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|679|9.7%|38.5%|
[firehol_level3](#firehol_level3)|40636|377754|601|0.1%|34.1%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|600|2.0%|34.0%|
[xroxy](#xroxy)|2119|2119|400|18.8%|22.7%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|394|6.3%|22.3%|
[firehol_level2](#firehol_level2)|19001|517810|265|0.0%|15.0%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|265|8.2%|15.0%|
[blocklist_de](#blocklist_de)|29751|29751|265|0.8%|15.0%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|253|9.9%|14.3%|
[proxz](#proxz)|1001|1001|246|24.5%|13.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|65|0.0%|3.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|53|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|34|0.0%|1.9%|
[nixspam](#nixspam)|39998|39998|8|0.0%|0.4%|
[php_commenters](#php_commenters)|373|373|7|1.8%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.3%|
[php_spammers](#php_spammers)|580|580|4|0.6%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|3|1.8%|0.1%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.1%|
[php_dictionary](#php_dictionary)|589|589|2|0.3%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5010|688456731|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Sun Jun  7 21:51:33 UTC 2015.

The ipset `proxz` has **1001** entries, **1001** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11468|11689|1001|8.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|1001|1.3%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|606|0.6%|60.5%|
[firehol_level3](#firehol_level3)|40636|377754|462|0.1%|46.1%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|458|6.5%|45.7%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|450|1.5%|44.9%|
[xroxy](#xroxy)|2119|2119|370|17.4%|36.9%|
[proxyrss](#proxyrss)|1762|1762|246|13.9%|24.5%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|166|6.5%|16.5%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|164|2.6%|16.3%|
[firehol_level2](#firehol_level2)|19001|517810|133|0.0%|13.2%|
[blocklist_de](#blocklist_de)|29751|29751|133|0.4%|13.2%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|108|3.3%|10.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|83|0.0%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|38|0.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|36|0.0%|3.5%|
[nixspam](#nixspam)|39998|39998|26|0.0%|2.5%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|23|0.1%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|20|0.2%|1.9%|
[php_spammers](#php_spammers)|580|580|18|3.1%|1.7%|
[php_dictionary](#php_dictionary)|589|589|17|2.8%|1.6%|
[php_commenters](#php_commenters)|373|373|7|1.8%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|6|0.9%|0.5%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|3|0.0%|0.2%|
[firehol_level1](#firehol_level1)|5010|688456731|2|0.0%|0.1%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.1%|
[dshield](#dshield)|20|5120|2|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|2|0.1%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|2|1.2%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|2|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|1|0.0%|0.0%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Sun Jun  7 22:16:59 UTC 2015.

The ipset `ri_connect_proxies` has **2547** entries, **2547** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11468|11689|2547|21.7%|100.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|2547|3.3%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1456|1.5%|57.1%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|1077|15.4%|42.2%|
[firehol_level3](#firehol_level3)|40636|377754|646|0.1%|25.3%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|643|2.1%|25.2%|
[xroxy](#xroxy)|2119|2119|372|17.5%|14.6%|
[proxyrss](#proxyrss)|1762|1762|253|14.3%|9.9%|
[proxz](#proxz)|1001|1001|166|16.5%|6.5%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|139|2.2%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|97|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|79|0.0%|3.1%|
[firehol_level2](#firehol_level2)|19001|517810|64|0.0%|2.5%|
[blocklist_de](#blocklist_de)|29751|29751|64|0.2%|2.5%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|60|1.8%|2.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|54|0.0%|2.1%|
[nixspam](#nixspam)|39998|39998|8|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|7|1.0%|0.2%|
[php_commenters](#php_commenters)|373|373|5|1.3%|0.1%|
[php_dictionary](#php_dictionary)|589|589|4|0.6%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|3|0.0%|0.1%|
[php_spammers](#php_spammers)|580|580|3|0.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|3|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Sun Jun  7 22:15:15 UTC 2015.

The ipset `ri_web_proxies` has **6963** entries, **6963** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11468|11689|6963|59.5%|100.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|6963|9.2%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|3347|3.6%|48.0%|
[firehol_level3](#firehol_level3)|40636|377754|1709|0.4%|24.5%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1654|5.5%|23.7%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|1077|42.2%|15.4%|
[xroxy](#xroxy)|2119|2119|920|43.4%|13.2%|
[proxyrss](#proxyrss)|1762|1762|679|38.5%|9.7%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|518|8.2%|7.4%|
[proxz](#proxz)|1001|1001|458|45.7%|6.5%|
[firehol_level2](#firehol_level2)|19001|517810|390|0.0%|5.6%|
[blocklist_de](#blocklist_de)|29751|29751|390|1.3%|5.6%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|324|10.1%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|200|0.0%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|198|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|136|0.0%|1.9%|
[nixspam](#nixspam)|39998|39998|70|0.1%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|63|0.3%|0.9%|
[php_dictionary](#php_dictionary)|589|589|47|7.9%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|46|0.4%|0.6%|
[php_spammers](#php_spammers)|580|580|42|7.2%|0.6%|
[php_commenters](#php_commenters)|373|373|23|6.1%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|9|0.3%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|5|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6434|6434|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6476|6476|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|3|1.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|2|0.0%|0.0%|
[sslbl](#sslbl)|381|381|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[firehol_level1](#firehol_level1)|5010|688456731|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Sun Jun  7 23:30:05 UTC 2015.

The ipset `shunlist` has **1206** entries, **1206** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level3](#firehol_level3)|40636|377754|1206|0.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|1200|0.6%|99.5%|
[openbl_60d](#openbl_60d)|7239|7239|526|7.2%|43.6%|
[openbl_30d](#openbl_30d)|3048|3048|508|16.6%|42.1%|
[et_compromised](#et_compromised)|2016|2016|423|20.9%|35.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|400|23.7%|33.1%|
[firehol_level2](#firehol_level2)|19001|517810|394|0.0%|32.6%|
[blocklist_de](#blocklist_de)|29751|29751|354|1.1%|29.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|318|10.5%|26.3%|
[openbl_7d](#openbl_7d)|815|815|216|26.5%|17.9%|
[firehol_level1](#firehol_level1)|5010|688456731|178|0.0%|14.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|108|0.0%|8.9%|
[et_block](#et_block)|1023|18338662|108|0.0%|8.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|93|0.0%|7.7%|
[dshield](#dshield)|20|5120|93|1.8%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|65|0.0%|5.3%|
[sslbl](#sslbl)|381|381|58|15.2%|4.8%|
[openbl_1d](#openbl_1d)|101|101|47|46.5%|3.8%|
[ciarmy](#ciarmy)|443|443|35|7.9%|2.9%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|31|0.1%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|28|0.0%|2.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|21|13.2%|1.7%|
[voipbl](#voipbl)|10491|10902|11|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|4|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|4|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|2|0.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|1|0.0%|0.0%|
[nixspam](#nixspam)|39998|39998|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11468|11689|1|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6434|6434|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6476|6476|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|1|1.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|1|0.0%|0.0%|

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
[et_tor](#et_tor)|6470|6470|1073|16.5%|11.4%|
[bm_tor](#bm_tor)|6476|6476|1061|16.3%|11.2%|
[dm_tor](#dm_tor)|6434|6434|1047|16.2%|11.1%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|788|0.8%|8.3%|
[firehol_level3](#firehol_level3)|40636|377754|692|0.1%|7.3%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|598|2.0%|6.3%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|376|6.0%|3.9%|
[firehol_level2](#firehol_level2)|19001|517810|339|0.0%|3.6%|
[et_block](#et_block)|1023|18338662|315|0.0%|3.3%|
[nixspam](#nixspam)|39998|39998|307|0.7%|3.2%|
[firehol_level1](#firehol_level1)|5010|688456731|275|0.0%|2.9%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|242|0.3%|2.5%|
[firehol_proxies](#firehol_proxies)|11468|11689|240|2.0%|2.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|236|0.0%|2.5%|
[zeus](#zeus)|234|234|204|87.1%|2.1%|
[zeus_badips](#zeus_badips)|203|203|179|88.1%|1.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|174|46.7%|1.8%|
[blocklist_de](#blocklist_de)|29751|29751|135|0.4%|1.4%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|116|0.0%|1.2%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|108|0.6%|1.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|103|0.0%|1.0%|
[feodo](#feodo)|99|99|79|79.7%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|76|0.0%|0.8%|
[php_dictionary](#php_dictionary)|589|589|66|11.2%|0.7%|
[php_spammers](#php_spammers)|580|580|61|10.5%|0.6%|
[php_commenters](#php_commenters)|373|373|51|13.6%|0.5%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|46|0.6%|0.4%|
[xroxy](#xroxy)|2119|2119|32|1.5%|0.3%|
[sslbl](#sslbl)|381|381|31|8.1%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|28|2.1%|0.2%|
[openbl_60d](#openbl_60d)|7239|7239|26|0.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|20|0.0%|0.2%|
[proxz](#proxz)|1001|1001|20|1.9%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|19|0.5%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|15|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.1%|
[php_harvesters](#php_harvesters)|341|341|11|3.2%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|8|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|8|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3048|3048|4|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|4|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|3|0.0%|0.0%|
[shunlist](#shunlist)|1206|1206|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1762|1762|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|815|815|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|1|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|482|482|1|0.2%|0.0%|

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
[firehol_level1](#firehol_level1)|5010|688456731|18338560|2.6%|100.0%|
[et_block](#et_block)|1023|18338662|18054912|98.4%|98.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8532506|2.4%|46.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6932480|75.5%|37.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|2272265|0.2%|12.3%|
[fullbogons](#fullbogons)|3720|670264216|151552|0.0%|0.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|130368|0.0%|0.7%|
[firehol_level3](#firehol_level3)|40636|377754|1527|0.4%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|1374|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1017|1.1%|0.0%|
[firehol_level2](#firehol_level2)|19001|517810|706|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|314|1.0%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|239|3.3%|0.0%|
[blocklist_de](#blocklist_de)|29751|29751|176|0.5%|0.0%|
[openbl_30d](#openbl_30d)|3048|3048|124|4.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|108|3.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|101|6.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|100|4.9%|0.0%|
[shunlist](#shunlist)|1206|1206|93|7.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|80|1.2%|0.0%|
[nixspam](#nixspam)|39998|39998|70|0.1%|0.0%|
[openbl_7d](#openbl_7d)|815|815|42|5.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|41|1.2%|0.0%|
[php_commenters](#php_commenters)|373|373|29|7.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|23|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|20|0.2%|0.0%|
[zeus_badips](#zeus_badips)|203|203|16|7.8%|0.0%|
[zeus](#zeus)|234|234|16|6.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|16|0.6%|0.0%|
[voipbl](#voipbl)|10491|10902|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|101|101|8|7.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|6|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|6|3.7%|0.0%|
[php_dictionary](#php_dictionary)|589|589|5|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|5|0.0%|0.0%|
[php_spammers](#php_spammers)|580|580|4|0.6%|0.0%|
[malc0de](#malc0de)|351|351|4|1.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|4|0.0%|0.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6434|6434|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6476|6476|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|2|0.3%|0.0%|
[firehol_proxies](#firehol_proxies)|11468|11689|2|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[sslbl](#sslbl)|381|381|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|224|224|1|0.4%|0.0%|
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
[firehol_level2](#firehol_level2)|19001|517810|487424|94.1%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|98904|0.0%|20.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|33155|0.0%|6.8%|
[firehol_level1](#firehol_level1)|5010|688456731|517|0.0%|0.1%|
[et_block](#et_block)|1023|18338662|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|512|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|79|0.0%|0.0%|
[firehol_level3](#firehol_level3)|40636|377754|16|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|15|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|10|0.0%|0.0%|
[php_commenters](#php_commenters)|373|373|7|1.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|203|203|5|2.4%|0.0%|
[zeus](#zeus)|234|234|5|2.1%|0.0%|
[blocklist_de](#blocklist_de)|29751|29751|4|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|3|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|2|0.0%|0.0%|
[nixspam](#nixspam)|39998|39998|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|2|1.2%|0.0%|
[php_harvesters](#php_harvesters)|341|341|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3048|3048|1|0.0%|0.0%|
[malc0de](#malc0de)|351|351|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6434|6434|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Mon Jun  8 00:30:05 UTC 2015.

The ipset `sslbl` has **381** entries, **381** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level1](#firehol_level1)|5010|688456731|381|0.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|64|0.0%|16.7%|
[firehol_level3](#firehol_level3)|40636|377754|59|0.0%|15.4%|
[shunlist](#shunlist)|1206|1206|58|4.8%|15.2%|
[feodo](#feodo)|99|99|36|36.3%|9.4%|
[et_block](#et_block)|1023|18338662|35|0.0%|9.1%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|31|0.3%|8.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|29|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|4|0.0%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.2%|
[firehol_proxies](#firehol_proxies)|11468|11689|1|0.0%|0.2%|
[firehol_level2](#firehol_level2)|19001|517810|1|0.0%|0.2%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|29751|29751|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Mon Jun  8 00:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6250** entries, **6250** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|6250|6.7%|100.0%|
[firehol_level3](#firehol_level3)|40636|377754|3754|0.9%|60.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|3742|12.5%|59.8%|
[firehol_level2](#firehol_level2)|19001|517810|1351|0.2%|21.6%|
[blocklist_de](#blocklist_de)|29751|29751|1348|4.5%|21.5%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|1301|40.7%|20.8%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|893|1.1%|14.2%|
[firehol_proxies](#firehol_proxies)|11468|11689|886|7.5%|14.1%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|518|7.4%|8.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|461|0.0%|7.3%|
[proxyrss](#proxyrss)|1762|1762|394|22.3%|6.3%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|376|3.9%|6.0%|
[bm_tor](#bm_tor)|6476|6476|347|5.3%|5.5%|
[dm_tor](#dm_tor)|6434|6434|346|5.3%|5.5%|
[et_tor](#et_tor)|6470|6470|342|5.2%|5.4%|
[xroxy](#xroxy)|2119|2119|274|12.9%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|192|0.0%|3.0%|
[proxz](#proxz)|1001|1001|164|16.3%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|151|40.5%|2.4%|
[php_commenters](#php_commenters)|373|373|146|39.1%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|139|5.4%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|130|0.0%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|86|54.4%|1.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|80|0.0%|1.2%|
[firehol_level1](#firehol_level1)|5010|688456731|80|0.0%|1.2%|
[et_block](#et_block)|1023|18338662|74|0.0%|1.1%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|50|0.2%|0.8%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|49|0.0%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|46|0.2%|0.7%|
[php_harvesters](#php_harvesters)|341|341|41|12.0%|0.6%|
[nixspam](#nixspam)|39998|39998|38|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|33|0.0%|0.5%|
[php_spammers](#php_spammers)|580|580|26|4.4%|0.4%|
[php_dictionary](#php_dictionary)|589|589|25|4.2%|0.4%|
[openbl_60d](#openbl_60d)|7239|7239|21|0.2%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|9|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|7|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|5|0.7%|0.0%|
[voipbl](#voipbl)|10491|10902|4|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|234|234|1|0.4%|0.0%|
[shunlist](#shunlist)|1206|1206|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3048|3048|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|1|0.0%|0.0%|

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
[firehol_level3](#firehol_level3)|40636|377754|30064|7.9%|32.5%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|29870|100.0%|32.3%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|6250|100.0%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|5743|0.0%|6.2%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|5323|7.0%|5.7%|
[firehol_proxies](#firehol_proxies)|11468|11689|5153|44.0%|5.5%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|3347|48.0%|3.6%|
[firehol_level2](#firehol_level2)|19001|517810|2592|0.5%|2.8%|
[blocklist_de](#blocklist_de)|29751|29751|2510|8.4%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|2489|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|2196|68.7%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|1511|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|1456|57.1%|1.5%|
[xroxy](#xroxy)|2119|2119|1254|59.1%|1.3%|
[firehol_level1](#firehol_level1)|5010|688456731|1020|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1017|0.0%|1.1%|
[et_block](#et_block)|1023|18338662|1008|0.0%|1.0%|
[proxyrss](#proxyrss)|1762|1762|853|48.4%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|788|8.3%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|732|0.0%|0.7%|
[et_tor](#et_tor)|6470|6470|660|10.2%|0.7%|
[dm_tor](#dm_tor)|6434|6434|645|10.0%|0.6%|
[bm_tor](#bm_tor)|6476|6476|644|9.9%|0.6%|
[proxz](#proxz)|1001|1001|606|60.5%|0.6%|
[php_commenters](#php_commenters)|373|373|277|74.2%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|244|1.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|232|62.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|198|0.1%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|197|1.1%|0.2%|
[nixspam](#nixspam)|39998|39998|174|0.4%|0.1%|
[php_spammers](#php_spammers)|580|580|122|21.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|117|74.0%|0.1%|
[php_dictionary](#php_dictionary)|589|589|111|18.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|79|0.0%|0.0%|
[php_harvesters](#php_harvesters)|341|341|78|22.8%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|54|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|47|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|46|0.0%|0.0%|
[voipbl](#voipbl)|10491|10902|37|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|20|3.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|16|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|15|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|13|0.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|13|0.5%|0.0%|
[et_compromised](#et_compromised)|2016|2016|11|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|482|482|8|1.6%|0.0%|
[shunlist](#shunlist)|1206|1206|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3048|3048|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|4|0.3%|0.0%|
[openbl_7d](#openbl_7d)|815|815|3|0.3%|0.0%|
[zeus_badips](#zeus_badips)|203|203|2|0.9%|0.0%|
[zeus](#zeus)|234|234|2|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3720|670264216|2|0.0%|0.0%|
[openbl_1d](#openbl_1d)|101|101|1|0.9%|0.0%|
[ciarmy](#ciarmy)|443|443|1|0.2%|0.0%|
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
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|29870|32.3%|100.0%|
[firehol_level3](#firehol_level3)|40636|377754|29870|7.9%|100.0%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|3742|59.8%|12.5%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|2575|3.4%|8.6%|
[firehol_proxies](#firehol_proxies)|11468|11689|2522|21.5%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1948|0.0%|6.5%|
[firehol_level2](#firehol_level2)|19001|517810|1933|0.3%|6.4%|
[blocklist_de](#blocklist_de)|29751|29751|1923|6.4%|6.4%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|1756|54.9%|5.8%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|1654|23.7%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|882|0.0%|2.9%|
[xroxy](#xroxy)|2119|2119|695|32.7%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|643|25.2%|2.1%|
[proxyrss](#proxyrss)|1762|1762|600|34.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|598|6.3%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|559|0.0%|1.8%|
[et_tor](#et_tor)|6470|6470|516|7.9%|1.7%|
[dm_tor](#dm_tor)|6434|6434|495|7.6%|1.6%|
[bm_tor](#bm_tor)|6476|6476|494|7.6%|1.6%|
[proxz](#proxz)|1001|1001|450|44.9%|1.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|314|0.0%|1.0%|
[firehol_level1](#firehol_level1)|5010|688456731|314|0.0%|1.0%|
[et_block](#et_block)|1023|18338662|308|0.0%|1.0%|
[php_commenters](#php_commenters)|373|373|202|54.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|189|50.8%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|150|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|138|0.7%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|115|0.6%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|105|66.4%|0.3%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|95|0.0%|0.3%|
[nixspam](#nixspam)|39998|39998|92|0.2%|0.3%|
[php_dictionary](#php_dictionary)|589|589|71|12.0%|0.2%|
[php_spammers](#php_spammers)|580|580|66|11.3%|0.2%|
[php_harvesters](#php_harvesters)|341|341|58|17.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|27|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|25|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7239|7239|24|0.3%|0.0%|
[voipbl](#voipbl)|10491|10902|14|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|12|1.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|10|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|8|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|7|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|7|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|7|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3028|3028|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|482|482|3|0.6%|0.0%|
[shunlist](#shunlist)|1206|1206|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1450|1450|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|203|203|1|0.4%|0.0%|
[zeus](#zeus)|234|234|1|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3048|3048|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1288|1288|1|0.0%|0.0%|
[ciarmy](#ciarmy)|443|443|1|0.2%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Mon Jun  8 00:07:01 UTC 2015.

The ipset `virbl` has **0** entries, **0** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Mon Jun  8 00:27:04 UTC 2015.

The ipset `voipbl` has **10491** entries, **10902** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|1600|0.0%|14.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|434|0.0%|3.9%|
[firehol_level1](#firehol_level1)|5010|688456731|336|0.0%|3.0%|
[fullbogons](#fullbogons)|3720|670264216|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|299|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|196|0.1%|1.7%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|75|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|37|0.0%|0.3%|
[firehol_level2](#firehol_level2)|19001|517810|35|0.0%|0.3%|
[blocklist_de](#blocklist_de)|29751|29751|35|0.1%|0.3%|
[firehol_level3](#firehol_level3)|40636|377754|33|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|30|32.6%|0.2%|
[et_block](#et_block)|1023|18338662|18|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|14|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|14|0.0%|0.1%|
[shunlist](#shunlist)|1206|1206|11|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7239|7239|8|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|4|0.0%|0.0%|
[ciarmy](#ciarmy)|443|443|4|0.9%|0.0%|
[openbl_30d](#openbl_30d)|3048|3048|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6434|6434|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6476|6476|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|3|0.0%|0.0%|
[nixspam](#nixspam)|39998|39998|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|2|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[firehol_proxies](#firehol_proxies)|11468|11689|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Mon Jun  8 00:33:03 UTC 2015.

The ipset `xroxy` has **2119** entries, **2119** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_proxies](#firehol_proxies)|11468|11689|2119|18.1%|100.0%|
[firehol_anonymous](#firehol_anonymous)|11675|75595|2119|2.8%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|1254|1.3%|59.1%|
[ri_web_proxies](#ri_web_proxies)|6963|6963|920|13.2%|43.4%|
[firehol_level3](#firehol_level3)|40636|377754|721|0.1%|34.0%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|695|2.3%|32.7%|
[proxyrss](#proxyrss)|1762|1762|400|22.7%|18.8%|
[ri_connect_proxies](#ri_connect_proxies)|2547|2547|372|14.6%|17.5%|
[proxz](#proxz)|1001|1001|370|36.9%|17.4%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|274|4.3%|12.9%|
[firehol_level2](#firehol_level2)|19001|517810|194|0.0%|9.1%|
[blocklist_de](#blocklist_de)|29751|29751|194|0.6%|9.1%|
[blocklist_de_bots](#blocklist_de_bots)|3194|3194|152|4.7%|7.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|104|0.0%|4.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|99|0.0%|4.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|58|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|40|0.2%|1.8%|
[nixspam](#nixspam)|39998|39998|38|0.0%|1.7%|
[php_dictionary](#php_dictionary)|589|589|35|5.9%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|32|0.3%|1.5%|
[php_spammers](#php_spammers)|580|580|27|4.6%|1.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|663|663|13|1.9%|0.6%|
[php_commenters](#php_commenters)|373|373|8|2.1%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|158|158|4|2.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|4|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|47940|47940|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|341|341|2|0.5%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|16518|16518|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2016|2016|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6434|6434|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|1681|1681|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6476|6476|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|5186|5186|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Sun Jun  7 21:42:20 UTC 2015.

The ipset `zeus` has **234** entries, **234** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[firehol_level2](#firehol_level2)|19001|517810|234|0.0%|100.0%|
[et_block](#et_block)|1023|18338662|224|0.0%|95.7%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|204|2.1%|87.1%|
[zeus_badips](#zeus_badips)|203|203|203|100.0%|86.7%|
[firehol_level1](#firehol_level1)|5010|688456731|203|0.0%|86.7%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|63|0.0%|26.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|13|0.0%|5.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|9|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|6|0.0%|2.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.1%|
[firehol_level3](#firehol_level3)|40636|377754|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7239|7239|2|0.0%|0.8%|
[openbl_30d](#openbl_30d)|3048|3048|2|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|1|0.0%|0.4%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.4%|
[nixspam](#nixspam)|39998|39998|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|1|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|29751|29751|1|0.0%|0.4%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Mon Jun  8 00:18:09 UTC 2015.

The ipset `zeus_badips` has **203** entries, **203** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|234|234|203|86.7%|100.0%|
[firehol_level2](#firehol_level2)|19001|517810|203|0.0%|100.0%|
[firehol_level1](#firehol_level1)|5010|688456731|203|0.0%|100.0%|
[et_block](#et_block)|1023|18338662|200|0.0%|98.5%|
[snort_ipfilter](#snort_ipfilter)|9408|9408|179|1.9%|88.1%|
[alienvault_reputation](#alienvault_reputation)|176509|176509|37|0.0%|18.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17812|139104927|10|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72950|348710251|8|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|487424|5|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218307|764993634|4|0.0%|1.9%|
[firehol_level3](#firehol_level3)|40636|377754|3|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|92247|92247|2|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|29870|29870|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6250|6250|1|0.0%|0.4%|
[php_commenters](#php_commenters)|373|373|1|0.2%|0.4%|
[openbl_60d](#openbl_60d)|7239|7239|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3048|3048|1|0.0%|0.4%|
[nixspam](#nixspam)|39998|39998|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3267|339173|1|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|17557|17557|1|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|2376|2376|1|0.0%|0.4%|
[blocklist_de](#blocklist_de)|29751|29751|1|0.0%|0.4%|
