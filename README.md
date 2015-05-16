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
alienvault_reputation|ipv4|hash:ip|175552|Sat May 16 15:36:40 UTC 2015|[source](https://reputation.alienvault.com/reputation.generic?r=9153)
blocklist_de|ipv4|hash:ip|22783|Sat May 16 18:09:14 UTC 2015|[source](http://lists.blocklist.de/lists/all.txt?r=12529)
bogons|ipv4|hash:net|13|Wed May 13 19:14:57 UTC 2015|[source](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt?r=1780)
botnet|ipv4|hash:ip|395|Sat May 16 11:09:19 UTC 2015|[source](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules?r=27013)
bruteforceblocker|ipv4|hash:ip|2075|Sat May 16 18:00:12 UTC 2015|[source](http://danger.rulez.sk/projects/bruteforceblocker/blist.php?r=12933)
ciarmy|ipv4|hash:ip|413|Sat May 16 18:00:06 UTC 2015|[source](http://cinsscore.com/list/ci-badguys.txt?r=513)
clean_mx_viruses|ipv4|hash:ip|269|Sat May 16 07:45:39 UTC 2015|[source](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
compromised|ipv4|hash:ip|2077|Sat May 16 12:36:08 UTC 2015|[source](http://rules.emergingthreats.net/blockrules/compromised-ips.txt?r=27475)
danmetor|ipv4|hash:ip|5662|Sat May 16 17:36:09 UTC 2015|[source](https://www.dan.me.uk/torlist/?r=25669)
dshield|ipv4|hash:net|20|Sat May 16 16:32:51 UTC 2015|[source](http://feeds.dshield.org/block.txt?r=12547)
emerging_block|ipv4|hash:net|992|Sat May 16 12:36:13 UTC 2015|[source](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt?r=27115)
feodo|ipv4|hash:ip|28|Sat May 16 17:00:00 UTC 2015|[source](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist&r=19345)
fullbogons|ipv4|hash:net|3380|Sat May 16 12:54:11 UTC 2015|[source](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt?r=26354)
ib_bluetack_badpeers|ipv4|hash:ip|40807|Sat May 16 13:54:12 UTC 2015|[source](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
ib_bluetack_hijacked|ipv4|hash:net|404|Sat May 16 13:54:17 UTC 2015|[source](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
ib_bluetack_level1|ipv4|hash:net|174228|Sat May 16 03:21:50 UTC 2015|[source](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
ib_bluetack_level2|ipv4|hash:net|58994|Sat May 16 03:25:57 UTC 2015|[source](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
ib_bluetack_level3|ipv4|hash:net|14248|Sat May 16 03:26:37 UTC 2015|[source](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz)
ib_bluetack_proxies|ipv4|hash:ip|521|Sat May 16 13:36:25 UTC 2015|[source](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
ib_bluetack_spyware|iBlocklist.com free version of BlueTack.co.uk known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|898|Sat May 16 18:26:34 UTC 2015||[source](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
ib_bluetack_webexploit|ipv4|hash:ip|1159|Sat May 16 13:54:21 UTC 2015|[source](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
infiltrated|ipv4|hash:ip|7844|Sat May 16 08:27:24 UTC 2015|[source](http://www.infiltrated.net/blacklisted?r=27071)
malc0de|ipv4|hash:ip|328|Sat May 16 12:54:06 UTC 2015|[source](http://malc0de.com/bl/IP_Blacklist.txt?r=10802)
malwaredomainlist|ipv4|hash:ip|1091|Sat May 16 06:09:43 UTC 2015|[source](http://www.malwaredomainlist.com/hostslist/ip.txt?r=24878)
openbl|ipv4|hash:ip|7224|Sat May 16 15:00:06 UTC 2015|[source](http://www.openbl.org/lists/base.txt?r=31786)
palevo|ipv4|hash:ip|12|Sat May 16 17:36:31 UTC 2015|[source](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist&r=22163)
rosi_connect_proxies|ipv4|hash:ip|217|Sat May 16 16:11:28 UTC 2015|[source](http://tools.rosinstrument.com/proxy/plab100.xml?r=15024)
rosi_web_proxies|ipv4|hash:ip|338|Sat May 16 16:11:15 UTC 2015|[source](http://tools.rosinstrument.com/proxy/l100.xml?r=23525)
snort_ipfilter|ipv4|hash:ip|5708|Sat May 16 16:11:47 UTC 2015|[source](http://labs.snort.org/feeds/ip-filter.blf?r=17518)
spamhaus_drop|ipv4|hash:net|445|Sat May 16 12:36:18 UTC 2015|[source](http://www.spamhaus.org/drop/drop.txt?r=32309)
spamhaus_edrop|ipv4|hash:net|38|Sat May 16 12:36:23 UTC 2015|[source](http://www.spamhaus.org/drop/edrop.txt?r=23000)
stop_forum_spam_1h|ipv4|hash:ip|4739|Sat May 16 17:36:38 UTC 2015|[source](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
stop_forum_spam_30d|ipv4|hash:ip|74856|Sat May 16 08:54:14 UTC 2015|[source](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stop_forum_spam_7d|StopForumSpam.com last 7 days IPs used by forum spammers|ipv4 hash:ip|29670|Sat May 16 18:35:29 UTC 2015||[source](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
tor|ipv4|hash:ip|5567|Sat May 16 11:09:14 UTC 2015|[source](http://rules.emergingthreats.net/blockrules/emerging-tor.rules?r=4848)
tor_servers|ipv4|hash:ip|5670|Sat May 16 17:36:14 UTC 2015|[source](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv?r=21603)
zeus|ipv4|hash:ip|210|Sat May 16 11:18:21 UTC 2015|[source](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist&r=29716)
zeus_badips|ipv4|hash:ip|187|Sat May 16 16:59:49 UTC 2015|[source](https://zeustracker.abuse.ch/blocklist.php?download=badips&r=22888)
