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
script.

Using blocklists at the internet side of your firewall is a key component of internet security.
These lists share key knowledge between us, allowing us to learn from each other and effectively
isolate fraudsters and attackers from our services.

I decided to upload these lists to a github repo because:

1. They are freely available on the internet. The intention of their creators is to help internet security.
 Keep in mind though that a few of these lists may have special licences attached. Before using them, please
 check their source site for any information regarding proper use.

2. Github provides (via `git pull`) a unified way of updating all the lists together. Pulling this repo regularly on your machines, you will update all the IP lists at once.

3. Github also provides a unified version control. Using it we can have a history of what each list has done, which IPs or subnets were added and which were removed.


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
TODO

### Updating the ipsets while the firewall is running
TODO

---

## Using them using plain iptables commands

### Creating the ipsets
TODO

### Updating the ipsets while the firewall is running
TODO

---

# List of ipsets included
name|info|type|entries|updated|frequency|links|
:--:|:--:|:--:|:-----:|:-----:|:-------:|:---:|
alienvault_reputation|AlienVault.com IP reputation database|ipv4 hash:ip|199957|Sat May 16 18:43:38 UTC 2015|12 hours |[source](https://reputation.alienvault.com/reputation.generic?r=8299)
blocklist_de|Blocklist.de IPs that have attacked their honeypots in the last 48 hours|ipv4 hash:ip|27858|Sat May 16 18:41:20 UTC 2015|30 mins |[source](http://lists.blocklist.de/lists/all.txt?r=19130)
bogons|Team-Cymru.org provided private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry|ipv4 hash:net|13|Sat May 16 18:42:12 UTC 2015|1 day |[source](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt?r=16867)
botnet|EmergingThreats.net botnet IPs (at the time of writing includes all abuse.ch trackers)|ipv4 hash:ip|477|Sat May 16 18:41:02 UTC 2015|12 hours |[source](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules?r=8848)
bruteforceblocker|danger.rulez.sk IPs detected by bruteforceblocker (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2694|Sat May 16 18:43:57 UTC 2015|3 hours |[source](http://danger.rulez.sk/projects/bruteforceblocker/blist.php?r=7764)
ciarmy|CIArmy.com IPs with poor Rogue Packet score that have not yet been identified as malicious by the InfoSec community|ipv4 hash:ip|481|Sat May 16 18:43:53 UTC 2015|3 hours |[source](http://cinsscore.com/list/ci-badguys.txt?r=23320)
clean_mx_viruses|Clean-MX.de IPs with viruses|ipv4 hash:ip|322|Sat May 16 18:43:48 UTC 2015|12 hours |[source](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
compromised|EmergingThreats.net distribution of IPs that have beed compromised (at the time of writing includes openbl and bruteforceblocker)|ipv4 hash:ip|2691|Sat May 16 18:40:57 UTC 2015|12 hours |[source](http://rules.emergingthreats.net/blockrules/compromised-ips.txt?r=20846)
danmetor|dan.me.uk dynamic list of TOR exit points|ipv4 hash:ip|6504|Sat May 16 18:40:44 UTC 2015|30 mins |[source](https://www.dan.me.uk/torlist/?r=22698)
dshield|DShield.org top 20 attacking networks|ipv4 hash:net|20|Sat May 16 18:40:40 UTC 2015|4 hours |[source](http://feeds.dshield.org/block.txt?r=26698)
emerging_block|EmergingThreats.net default blacklist (at the time of writing includes spamhaus DROP and dshield)|ipv4 hash:net|1302|Sat May 16 18:41:06 UTC 2015|12 hours |[source](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt?r=18311)
feodo||ipv4 hash:ip|33|Sat May 16 18:41:35 UTC 2015|30 mins |[source](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist&r=12133)
fullbogons|Team-Cymru.org provided IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user|ipv4 hash:net|3616|Sat May 16 18:42:16 UTC 2015|1 day |[source](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt?r=18517)
ib_bluetack_badpeers|iBlocklist.com free version of BlueTack.co.uk IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|48134|Sat May 16 18:44:20 UTC 2015|12 hours |[source](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
ib_bluetack_hijacked|iBlocklist.com free version of BlueTack.co.uk hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535|Sat May 16 18:44:24 UTC 2015|12 hours |[source](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
ib_bluetack_level1|iBlocklist.com free version of BlueTack.co.uk Level 1 (for use in p2p)|ipv4 hash:net|215693|Sat May 16 18:45:52 UTC 2015|12 hours |[source](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
ib_bluetack_level2|ipv4|hash:net|58994|Sat May 16 03:25:57 UTC 2015|[source](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
ib_bluetack_level3|iBlocklist.com free version of BlueTack.co.uk Level 3 (for use in p2p)|ipv4 hash:net|18550|Sat May 16 18:46:34 UTC 2015|12 hours |[source](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz)
ib_bluetack_proxies|iBlocklist.com free version of BlueTack.co.uk Open Proxies IPs (without TOR)|ipv4 hash:ip|673|Sat May 16 18:44:05 UTC 2015|12 hours |[source](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
ib_bluetack_spyware|iBlocklist.com free version of BlueTack.co.uk known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|898|Sat May 16 18:44:10 UTC 2015|12 hours |[source](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
ib_bluetack_webexploit|iBlocklist.com free version of BlueTack.co.uk web server hack and exploit attempts|ipv4 hash:ip|1460|Sat May 16 18:44:28 UTC 2015|12 hours |[source](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
infiltrated|infiltrated.net list (no more info available)|ipv4 hash:ip|10382|Sat May 16 18:41:40 UTC 2015|12 hours |[source](http://www.infiltrated.net/blacklisted?r=13504)
malc0de|Malc0de.com malicious IPs of the last 30 days|ipv4 hash:ip|371|Sat May 16 18:41:43 UTC 2015|1 day |[source](http://malc0de.com/bl/IP_Blacklist.txt?r=20969)
malwaredomainlist|malwaredomainlist.com list of active ip addresses|ipv4 hash:ip|1283|Sat May 16 18:43:14 UTC 2015|12 hours |[source](http://www.malwaredomainlist.com/hostslist/ip.txt?r=20415)
openbl|ipv4|hash:ip|7224|Sat May 16 15:00:06 UTC 2015|[source](http://www.openbl.org/lists/base.txt?r=31786)
palevo|Abuse.ch Palevo worm includes IPs which are being used as botnet C&C for the Palevo crimeware|ipv4 hash:ip|13|Sat May 16 18:41:31 UTC 2015|30 mins |[source](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist&r=9189)
rosi_connect_proxies|rosinstrument.com open CONNECT proxies distributed via its RSS feed and aggregated for the last 7 days|ipv4 hash:ip|295|Sat May 16 18:43:10 UTC 2015|2 hours |[source](http://tools.rosinstrument.com/proxy/plab100.xml?r=9320)
rosi_web_proxies|rosinstrument.com open HTTP proxies distributed via its RSS feed and aggregated for the last 7 days|ipv4 hash:ip|412|Sat May 16 18:42:55 UTC 2015|2 hours |[source](http://tools.rosinstrument.com/proxy/l100.xml?r=27810)
snort_ipfilter|labs.snort.org supplied IP blacklist|ipv4 hash:ip|6844|Sat May 16 18:44:01 UTC 2015|12 hours |[source](http://labs.snort.org/feeds/ip-filter.blf?r=17416)
spamhaus_drop|Spamhaus.org DROP list (according to their site this list should be dropped at tier-1 ISPs globaly)|ipv4 hash:net|636|Sat May 16 18:41:10 UTC 2015|12 hours |[source](http://www.spamhaus.org/drop/drop.txt?r=11751)
spamhaus_edrop|Spamhaus.org EDROP (should be used with DROP)|ipv4 hash:net|54|Sat May 16 18:41:14 UTC 2015|12 hours |[source](http://www.spamhaus.org/drop/edrop.txt?r=7191)
stop_forum_spam_1h|StopForumSpam.com last 24 hours IPs used by forum spammers|ipv4 hash:ip|5746|Sat May 16 18:41:48 UTC 2015|1 hour |[source](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
stop_forum_spam_30d|StopForumSpam.com last 30 days IPs used by forum spammers|ipv4 hash:ip|93853|Sat May 16 18:42:08 UTC 2015|1 day |[source](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stop_forum_spam_7d|StopForumSpam.com last 7 days IPs used by forum spammers|ipv4 hash:ip|29670|Sat May 16 18:41:55 UTC 2015|1 day |[source](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
tor|EmergingThreats.net list of TOR network IPs|ipv4 hash:ip|6420|Sat May 16 18:40:49 UTC 2015|12 hours |[source](http://rules.emergingthreats.net/blockrules/emerging-tor.rules?r=15379)
tor_servers|torstatus.blutmagie.de list of all TOR network servers|ipv4 hash:ip|6519|Sat May 16 18:40:53 UTC 2015|30 mins |[source](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv?r=4222)
zeus|Abuse.ch Zeus Tracker default blocklist including hijacked sites and web hosting providers|ipv4 hash:ip|262|Sat May 16 18:41:28 UTC 2015|30 mins |[source](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist&r=17726)
zeus_badips|Abuse.ch Zeus Tracker includes IPv4 addresses that are used by the ZeuS trojan|ipv4 hash:ip|228|Sat May 16 18:41:24 UTC 2015|30 mins |[source](https://zeustracker.abuse.ch/blocklist.php?download=badips&r=671)
