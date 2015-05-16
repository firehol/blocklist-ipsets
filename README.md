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
name|info|type|entries|freq|links|
:--:|:--:|:--:|:-----:|:--:|:---:|
alienvault_reputation|AlienVault.com IP reputation database|ipv4 hash:ip|199957|12 hours |[source](https://reputation.alienvault.com/reputation.generic?r=6740)
blocklist_de|Blocklist.de IPs that have attacked their honeypots in the last 48 hours|ipv4 hash:ip|27919|30 mins |[source](http://lists.blocklist.de/lists/all.txt?r=29400)
bogons|Team-Cymru.org provided private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry|ipv4 hash:net|13|1 day |[source](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt?r=170)
botnet|EmergingThreats.net botnet IPs (at the time of writing includes all abuse.ch trackers)|ipv4 hash:ip|477|12 hours |[source](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules?r=3356)
bruteforceblocker|danger.rulez.sk IPs detected by bruteforceblocker (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2694|3 hours |[source](http://danger.rulez.sk/projects/bruteforceblocker/blist.php?r=4588)
ciarmy|CIArmy.com IPs with poor Rogue Packet score that have not yet been identified as malicious by the InfoSec community|ipv4 hash:ip|481|3 hours |[source](http://cinsscore.com/list/ci-badguys.txt?r=10333)
clean_mx_viruses|Clean-MX.de IPs with viruses|ipv4 hash:ip|170|12 hours |[source](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
compromised|EmergingThreats.net distribution of IPs that have beed compromised (at the time of writing includes openbl and bruteforceblocker)|ipv4 hash:ip|2691|12 hours |[source](http://rules.emergingthreats.net/blockrules/compromised-ips.txt?r=1265)
danmetor|dan.me.uk dynamic list of TOR exit points|ipv4 hash:ip|6504|30 mins |[source](https://www.dan.me.uk/torlist/?r=24737)
dshield|DShield.org top 20 attacking networks|ipv4 hash:net|20|4 hours |[source](http://feeds.dshield.org/block.txt?r=16306)
emerging_block|EmergingThreats.net default blacklist (at the time of writing includes spamhaus DROP and dshield)|ipv4 hash:net|1302|12 hours |[source](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt?r=20669)
feodo||ipv4 hash:ip|33|30 mins |[source](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist&r=12950)
fullbogons|Team-Cymru.org provided IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user|ipv4 hash:net|3616|1 day |[source](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt?r=12498)
ib_bluetack_badpeers|iBlocklist.com free version of BlueTack.co.uk IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|48134|12 hours |[source](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
ib_bluetack_hijacked|iBlocklist.com free version of BlueTack.co.uk hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535|12 hours |[source](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
ib_bluetack_level1|iBlocklist.com free version of BlueTack.co.uk Level 1 (for use in p2p)|ipv4 hash:net|215693|12 hours |[source](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
ib_bluetack_level2|iBlocklist.com free version of BlueTack.co.uk Level 2 (for use in p2p)|ipv4 hash:net|75927|12 hours |[source](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
ib_bluetack_level3|iBlocklist.com free version of BlueTack.co.uk Level 3 (for use in p2p)|ipv4 hash:net|18550|12 hours |[source](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz)
ib_bluetack_proxies|iBlocklist.com free version of BlueTack.co.uk Open Proxies IPs (without TOR)|ipv4 hash:ip|673|12 hours |[source](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
ib_bluetack_spyware|iBlocklist.com free version of BlueTack.co.uk known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|898|12 hours |[source](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
ib_bluetack_webexploit|iBlocklist.com free version of BlueTack.co.uk web server hack and exploit attempts|ipv4 hash:ip|1460|12 hours |[source](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
infiltrated|infiltrated.net list (no more info available)|ipv4 hash:ip|10382|12 hours |[source](http://www.infiltrated.net/blacklisted?r=18577)
malc0de|Malc0de.com malicious IPs of the last 30 days|ipv4 hash:ip|371|1 day |[source](http://malc0de.com/bl/IP_Blacklist.txt?r=11963)
malwaredomainlist|malwaredomainlist.com list of active ip addresses|ipv4 hash:ip|1283|12 hours |[source](http://www.malwaredomainlist.com/hostslist/ip.txt?r=23688)
openbl|OpenBL.org default blacklist (currently it is the same with 90 days)|ipv4 hash:ip|9809|4 hours |[source](http://www.openbl.org/lists/base.txt.gz?r=29175)
openbl_1d|OpenBL.org last 24 hours IPs|ipv4 hash:ip|350|4 hours |[source](http://www.openbl.org/lists/base_1days.txt.gz?r=16600)
openbl_30d|OpenBL.org last 30 days IPs|ipv4 hash:ip|5136|4 hours |[source](http://www.openbl.org/lists/base_30days.txt.gz?r=23644)
openbl_60d|OpenBL.org last 60 days IPs|ipv4 hash:ip|7711|4 hours |[source](http://www.openbl.org/lists/base_60days.txt.gz?r=10050)
openbl_7d|OpenBL.org last 7 days IPs|ipv4 hash:ip|982|4 hours |[source](http://www.openbl.org/lists/base_7days.txt.gz?r=23013)
openbl_90d|OpenBL.org last 90 days IPs|ipv4 hash:ip|9809|4 hours |[source](http://www.openbl.org/lists/base_90days.txt.gz?r=1898)
palevo|Abuse.ch Palevo worm includes IPs which are being used as botnet C&C for the Palevo crimeware|ipv4 hash:ip|13|30 mins |[source](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist&r=29474)
rosi_connect_proxies|rosinstrument.com open CONNECT proxies distributed via its RSS feed and aggregated for the last 7 days|ipv4 hash:ip|295|2 hours |[source](http://tools.rosinstrument.com/proxy/plab100.xml?r=13838)
rosi_web_proxies|rosinstrument.com open HTTP proxies distributed via its RSS feed and aggregated for the last 7 days|ipv4 hash:ip|412|2 hours |[source](http://tools.rosinstrument.com/proxy/l100.xml?r=13258)
snort_ipfilter|labs.snort.org supplied IP blacklist|ipv4 hash:ip|6844|12 hours |[source](http://labs.snort.org/feeds/ip-filter.blf?r=18475)
spamhaus_drop|Spamhaus.org DROP list (according to their site this list should be dropped at tier-1 ISPs globaly)|ipv4 hash:net|636|12 hours |[source](http://www.spamhaus.org/drop/drop.txt?r=24954)
spamhaus_edrop|Spamhaus.org EDROP (should be used with DROP)|ipv4 hash:net|54|12 hours |[source](http://www.spamhaus.org/drop/edrop.txt?r=10164)
stop_forum_spam_1h|StopForumSpam.com last 24 hours IPs used by forum spammers|ipv4 hash:ip|5754|1 hour |[source](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
stop_forum_spam_30d|StopForumSpam.com last 30 days IPs used by forum spammers|ipv4 hash:ip|93853|1 day |[source](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stop_forum_spam_7d|StopForumSpam.com last 7 days IPs used by forum spammers|ipv4 hash:ip|29670|1 day |[source](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
tor|EmergingThreats.net list of TOR network IPs|ipv4 hash:ip|6420|12 hours |[source](http://rules.emergingthreats.net/blockrules/emerging-tor.rules?r=32167)
tor_servers|torstatus.blutmagie.de list of all TOR network servers|ipv4 hash:ip|6506|30 mins |[source](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv?r=17251)
zeus|Abuse.ch Zeus Tracker default blocklist including hijacked sites and web hosting providers|ipv4 hash:ip|262|30 mins |[source](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist&r=25939)
zeus_badips|Abuse.ch Zeus Tracker includes IPv4 addresses that are used by the ZeuS trojan|ipv4 hash:ip|228|30 mins |[source](https://zeustracker.abuse.ch/blocklist.php?download=badips&r=20505)
