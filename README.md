### Contents

- [About this repo](#about-this-repo)

- [Using these ipsets](#using-these-ipsets)
 - [Using them in FireHOL](#using-them-in-firehol)
    * [Adding the ipsets in your firehol.conf](#adding-the-ipsets-in-your-fireholconf)
    * [Updating the ipsets while the firewall is running](#updating-the-ipsets-while-the-firewall-is-running)
    
 - [Using them using plain iptables commands](#using-them-using-plain-iptables-commands)
    * [Creating the ipsets](#creating-the-ipsets) 
    * [Updating the ipsets while the firewall is running](#updating-the-ipsets-while-the-firewall-is-running)
    
- [Dynamic List of ipsets included](#list-of-ipsets-included)

---

# About this repo

This repository includes a list of ipsets dynamically updated with
firehol's (https://github.com/ktsaou/firehol) `update-ipsets.sh`
script found [here](https://github.com/ktsaou/firehol/blob/master/contrib/update-ipsets.sh).

This repo is self maintained. It it updated automatically from the script via a cron job.

## Why do we need blocklists?

As time passes and the internet matures in our life, cyber crime is becoming increasingly sophisticated.
Although there many tools (detection of malware, viruses, intrusion detection and prevension systems, etc)
to help us isolate the budguys, at the end of day they always manage to bypass all that.

What is more interesting is that the fraudsters or attackers in many cases are not going to do a
direct damage to you or your systems. They will use you and your systems to gain something else,
possibly not related or indirectly related to your business. Nowdays the attacks cannot be identified easily. They are
distributed and come to our systems from a vast amount of IPs around the world.

To get an idea, check for example the [XRumer](http://en.wikipedia.org/wiki/XRumer) software.

To increase our effectiveness we need to complement our security solutions with our 
shared knowledge, our shared experience in this fight.

Hopefully, there are many teams out there that do their best to identify the attacks and pinpoint
the attackers. These teams release blocklists. Blocklists of IPs (for use in firewalls), domains & URLs
(for use in proxies), etc.

What we are interested here is IPs.

Using IP blocklists at the internet side of your firewall is a key component of internet security.
These lists share key knowledge between us, allowing us to learn from each other and effectively
isolate fraudsters and attackers from our services.

I decided to upload these lists to a github repo because:

1. They are freely available on the internet. The intention of their creators is to help internet security.
 Keep in mind though that a few of these lists may have special licences attached. Before using them, please
 check their source site for any information regarding proper use.

2. Github provides (via `git pull`) a unified way of updating all the lists together.
 Pulling this repo regularly on your machines, you will update all the IP lists at once.

3. Github also provides a unified version control. Using it we can have a history of what each list has done,
 which IPs or subnets were added and which were removed.


---

# Using these ipsets
Please be very careful what you choose to use and how you use it.
If you blacklist traffic using these lists you may end up blocking
your users, your customers, even yourself (!) from accessing your
services.

1. Goto to the site of each list and read how each list is maintained. You are going to trust these guys for doing their job right.

2. Most sites have either a donation system or commercial lists of higher quality. Try to support them. 

3. I have included the TOR network in these lists (`danmetor`, `tor`, `tor_servers`). The TOR network is not necessarily bad and you should not block it if you want to allow your users be anonymous. I have included it because for certain cases, allowing an anonymity network might be a risky thing (such as eCommerce).

4. Apply any blacklist at the internet side of your firewall. Be very carefull. The `bogons` and `fullbogons` lists contain private, unroutable IPs that should not be routed on the internet. If you apply such a blocklist on your DMZ or LAN side, you will be blocked out of your firewall.

5. Always have a whitelist too, containing the IP addresses or subnets you trust. Try to build the rules in such a way that if an IP is in the whitelist, it should not be blocked by these blocklists.

---

## Using them in FireHOL

### Adding the ipsets in your firehol.conf

I use something like this. Keep in mind that you have to have the `whitelist` ipset created before all these.
iptables will log each match, together with the name of the ipset that matched the packet.

```sh
	# our wan interface
	wan="dsl0"
	
	# our whitelist
	ipset4 create whitelist hash:net
	ipset4 add whitelist A.B.C.D/E # A.B.C.D/E is whitelisted
	
	# subnets
	for x in fullbogons dshield spamhaus_drop spamhaus_edrop
	do
		ipset4 create  ${x} hash:net
		ipset4 addfile ${x} ipsets/${x}.netset
		blacklist4 full inface "${wan}" log "BLACKLIST ${x^^}" ipset:${x} \
			except src ipset:whitelist
	done

	# individual IPs
	for x in zeus feodo palevo autoshun openbl blocklist_de malc0de ciarmy \
		malwaredomainlist snort_ipfilter stop_forum_spam_1h stop_forum_spam_7d \
		bruteforceblocker rosi_connect_proxies rosi_web_proxies compromised
	do
		ipset4 create  ${x} hash:ip
		ipset4 addfile ${x} ipsets/${x}.ipset
		blacklist4 full inface "${wan}" log "BLACKLIST ${x^^}" ipset:${x} \
			except src ipset:whitelist
	done

	... rest of firehol.conf ...
```

### Updating the ipsets while the firewall is running

Just use the `update-ipsets.sh` script from the firehol distribution.
This script will update each ipset and call firehol to update the ipset while the firewall is running.

Keep in mind that you have to use the `update-ipsets.sh` script before activating the firewall, so that the ipsets exist on disk.

---

## Using them using plain iptables commands

### Creating the ipsets
TODO

### Updating the ipsets while the firewall is running
TODO

---

# List of ipsets included

The following list was automatically generated at Sun May 17 10:46:04 UTC 2015.

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
alienvault_reputation|AlienVault.com IP reputation database|ipv4 hash:ip|199869 unique IPs|updated every 12 hours  from [this link](https://reputation.alienvault.com/reputation.generic?r=10974)
autoshun|AutoShun.org IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|853 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv?r=18308)
blocklist_de|Blocklist.de IPs that have attacked their honeypots in the last 48 hours|ipv4 hash:ip|25510 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
bogons|Team-Cymru.org: private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry|ipv4 hash:net|13 entries, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt?r=12346)
botnet|EmergingThreats.net botnet IPs (at the time of writing includes all abuse.ch trackers)|ipv4 hash:ip|270 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules?r=14293)
bruteforceblocker|danger.rulez.sk IPs detected by bruteforceblocker (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2693 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php?r=7557)
ciarmy|CIArmy.com IPs with poor Rogue Packet score that have not yet been identified as malicious by the InfoSec community|ipv4 hash:ip|432 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt?r=503)
clean_mx_viruses|Clean-MX.de IPs with viruses|ipv4 hash:ip|338 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
compromised|EmergingThreats.net distribution of IPs that have beed compromised (at the time of writing includes openbl, bruteforceblocker and sidreporter)|ipv4 hash:ip|2698 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt?r=11392)
danmetor|dan.me.uk dynamic list of TOR exit points|ipv4 hash:ip|6473 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/?r=6560)
dshield|DShield.org top 20 attacking networks|ipv4 hash:net|19 entries, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt?r=29461)
emerging_block|EmergingThreats.net default blacklist (at the time of writing includes spamhaus DROP and dshield)|ipv4 hash:net|921 entries, 17934867 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt?r=8719)
feodo|Abuse.ch Feodo trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud|ipv4 hash:ip|36 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist&r=7278)
fullbogons|Team-Cymru.org: IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user|ipv4 hash:net|3618 entries, 671229912 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt?r=20234)
ib_bluetack_badpeers|iBlocklist.com free version of BlueTack.co.uk IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|48134 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
ib_bluetack_hijacked|iBlocklist.com free version of BlueTack.co.uk hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535 entries, 9177856 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
ib_bluetack_level1|iBlocklist.com free version of BlueTack.co.uk Level 1 (for use in p2p)|ipv4 hash:net|215693 entries, 765044590 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
ib_bluetack_level2|iBlocklist.com free version of BlueTack.co.uk Level 2 (for use in p2p)|ipv4 hash:net|75927 entries, 348729520 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
ib_bluetack_level3|iBlocklist.com free version of BlueTack.co.uk Level 3 (for use in p2p)|ipv4 hash:net|18550 entries, 139108857 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz)
ib_bluetack_proxies|iBlocklist.com free version of BlueTack.co.uk Open Proxies IPs (without TOR)|ipv4 hash:ip|673 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
ib_bluetack_spyware|iBlocklist.com free version of BlueTack.co.uk known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|898 entries, 336971 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
ib_bluetack_webexploit|iBlocklist.com free version of BlueTack.co.uk web server hack and exploit attempts|ipv4 hash:ip|1460 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
infiltrated|infiltrated.net list (no more info available)|ipv4 hash:ip|10397 unique IPs|updated every 12 hours  from [this link](http://www.infiltrated.net/blacklisted?r=5155)
malc0de|Malc0de.com malicious IPs of the last 30 days|ipv4 hash:ip|407 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt?r=6072)
malwaredomainlist|malwaredomainlist.com list of active ip addresses|ipv4 hash:ip|1283 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt?r=27685)
openbl|OpenBL.org default blacklist (currently it is the same with 90 days)|ipv4 hash:ip|9874 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt.gz?r=16688)
openbl_1d|OpenBL.org last 24 hours IPs|ipv4 hash:ip|383 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_1days.txt.gz?r=28925)
openbl_30d|OpenBL.org last 30 days IPs|ipv4 hash:ip|5079 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt.gz?r=7344)
openbl_60d|OpenBL.org last 60 days IPs|ipv4 hash:ip|7781 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt.gz?r=3147)
openbl_7d|OpenBL.org last 7 days IPs|ipv4 hash:ip|1031 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt.gz?r=8101)
openbl_90d|OpenBL.org last 90 days IPs|ipv4 hash:ip|9874 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt.gz?r=13452)
palevo|Abuse.ch Palevo worm includes IPs which are being used as botnet C&C for the Palevo crimeware|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist&r=13289)
rosi_connect_proxies|rosinstrument.com open CONNECT proxies distributed via its RSS feed and aggregated for the last 7 days|ipv4 hash:ip|426 unique IPs|updated every 2 hours  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml?r=27612)
rosi_web_proxies|rosinstrument.com open HTTP proxies distributed via its RSS feed and aggregated for the last 7 days|ipv4 hash:ip|617 unique IPs|updated every 2 hours  from [this link](http://tools.rosinstrument.com/proxy/l100.xml?r=21824)
snort_ipfilter|labs.snort.org supplied IP blacklist|ipv4 hash:ip|6474 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf?r=11412)
spamhaus_drop|Spamhaus.org DROP list (according to their site this list should be dropped at tier-1 ISPs globaly)|ipv4 hash:net|636 entries, 18060288 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt?r=4904)
spamhaus_edrop|Spamhaus.org EDROP (should be used with DROP)|ipv4 hash:net|54 entries, 419840 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt?r=23349)
stop_forum_spam_1h|StopForumSpam.com last 24 hours IPs used by forum spammers|ipv4 hash:ip|5558 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
stop_forum_spam_30d|StopForumSpam.com last 30 days IPs used by forum spammers|ipv4 hash:ip|92995 unique IPs|1 day |[src](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stop_forum_spam_7d|StopForumSpam.com last 7 days IPs used by forum spammers|ipv4 hash:ip|27726 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
tor|EmergingThreats.net list of TOR network IPs|ipv4 hash:ip|6350 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules?r=29231)
tor_servers|torstatus.blutmagie.de list of all TOR network servers|ipv4 hash:ip|6449 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv?r=28054)
zeus|Abuse.ch Zeus Tracker default blocklist including hijacked sites and web hosting providers|ipv4 hash:ip|263 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
zeus_badips|Abuse.ch Zeus Tracker includes IPv4 addresses that are used by the ZeuS trojan|ipv4 hash:ip|228 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips&r=31135)
