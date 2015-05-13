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

I decided to upload these lists to a github repo because:

1. They are free to use. The intention of their creators is to help internet security.

2. Github provides (via `git pull`) a unified way of updating all the lists together. Pulling this repo regularly on your machines, you will update all the IP lists at once.

3. Github also provides a unified version control. Using it we can have a history of what each list has done, which IPs or subnets were added and which were removed.

4. I have spent some time harvesting these lists, testing them and understanding how we can improve the security of public services. I have concluded that using such lists is a key component of internet security. These lists share key knowledge between us, allowing us to learn from each other and effectively isolate fraudsters and attackers from our services.

---

# Using these ipsets
Please be very careful what you choose to use and how you use it. If you blacklist traffic using these lists you may end up blocking your users, your customers, even yourself (!) from accessing your services.

1. Goto to the site of each list and read how each list is maintained. You are going to trust these guys for doing their job right.

2. Most sites have either a donation system or commercial lists of higher quality. Try to support them. 

3. Apply any blacklist at the internet side of your firewall. Be very carefull. The `bogons` and `fullbogons` lists contain private, unroutable IPs that should not be routed on the internet. If you apply such a blocklist on your DMZ or LAN side, you will be blocked out of your firewall.

4. Always have a whitelist too, containing the IP addresses or subnets you trust. Try to build the rules in such a way that if an IP is in the whitelist, it should not be blocked by these blocklists.

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
name|IP version|ipset type|entries|updated|source link|
:--:|:--------:|:--------:|:-----:|:-----:|:---------:|
blocklist_de|ipv4|hash:ip|37287|Wed May 13 20:27:09 UTC 2015|[source](http://lists.blocklist.de/lists/all.txt?r=27059)
bogons|ipv4|hash:net|13|Wed May 13 19:14:57 UTC 2015|[source](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt?r=1780)
botnet|ipv4|hash:ip|509|Wed May 13 19:14:24 UTC 2015|[source](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules?r=11460)
clean_mx_viruses|ipv4|hash:ip|29|Wed May 13 19:16:01 UTC 2015|[source](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
compromised|ipv4|hash:ip|2666|Wed May 13 19:14:22 UTC 2015|[source](http://rules.emergingthreats.net/blockrules/compromised-ips.txt?r=29423)
danmetor|ipv4|hash:ip|6458|Wed May 13 19:45:07 UTC 2015|[source](https://www.dan.me.uk/torlist/?r=5386)
dshield|ipv4|hash:net|20|Wed May 13 19:14:28 UTC 2015|[source](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules?r=261)
emerging_block|ipv4|hash:net|1284|Wed May 13 19:14:30 UTC 2015|[source](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt?r=28672)
fullbogons|ipv4|hash:net|3641|Wed May 13 19:14:59 UTC 2015|[source](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt?r=14737)
infiltrated|ipv4|hash:ip|10318|Wed May 13 19:14:45 UTC 2015|[source](http://www.infiltrated.net/blacklisted?r=4593)
malc0de|ipv4|hash:ip|213|Wed May 13 19:14:47 UTC 2015|[source](http://malc0de.com/bl/IP_Blacklist.txt?r=2645)
malwaredomainlist|ipv4|hash:ip|1283|Wed May 13 19:15:52 UTC 2015|[source](http://www.malwaredomainlist.com/hostslist/ip.txt?r=24222)
openbl|ipv4|hash:ip|9911|Wed May 13 19:14:12 UTC 2015|[source](http://www.openbl.org/lists/base.txt?r=29214)
rosi_connect_proxies|ipv4|hash:ip|152|Wed May 13 19:15:50 UTC 2015|[source](http://tools.rosinstrument.com/proxy/plab100.xml?r=12878)
rosi_web_proxies|ipv4|hash:ip|142|Wed May 13 19:15:32 UTC 2015|[source](http://tools.rosinstrument.com/proxy/l100.xml?r=30893)
spamhaus|ipv4|hash:net|631|Wed May 13 19:14:26 UTC 2015|[source](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules?r=3353)
spamhaus_drop|ipv4|hash:net|634|Wed May 13 19:14:33 UTC 2015|[source](http://www.spamhaus.org/drop/drop.txt?r=17177)
spamhaus_edrop|ipv4|hash:net|54|Wed May 13 19:14:35 UTC 2015|[source](http://www.spamhaus.org/drop/edrop.txt?r=19697)
stop_forum_spam_1h|ipv4|hash:ip|6470|Wed May 13 20:36:05 UTC 2015|[source](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
stop_forum_spam_7d|ipv4|hash:ip|31559|Wed May 13 19:14:55 UTC 2015|[source](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
tor|ipv4|hash:ip|6320|Wed May 13 19:14:17 UTC 2015|[source](http://rules.emergingthreats.net/blockrules/emerging-tor.rules?r=24649)
tor_servers|ipv4|hash:ip|6449|Wed May 13 19:14:20 UTC 2015|[source](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv?r=3940)
zeus|ipv4|hash:ip|258|Wed May 13 19:54:13 UTC 2015|[source](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist&r=29737)
