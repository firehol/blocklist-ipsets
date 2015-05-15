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
name|IP version|ipset type|entries|updated|source link|
:--:|:--------:|:--------:|:-----:|:-----:|:---------:|
blocklist_de|ipv4|hash:ip|33466|Fri May 15 22:09:09 UTC 2015|[source](http://lists.blocklist.de/lists/all.txt?r=29156)
bogons|ipv4|hash:net|13|Wed May 13 19:14:57 UTC 2015|[source](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt?r=1780)
botnet|ipv4|hash:ip|451|Fri May 15 10:54:08 UTC 2015|[source](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules?r=19286)
clean_mx_viruses|ipv4|hash:ip|347|Fri May 15 19:40:48 UTC 2015|[source](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
compromised|ipv4|hash:ip|2665|Fri May 15 00:36:06 UTC 2015|[source](http://rules.emergingthreats.net/blockrules/compromised-ips.txt?r=30721)
danmetor|ipv4|hash:ip|6418|Fri May 15 22:36:07 UTC 2015|[source](https://www.dan.me.uk/torlist/?r=14927)
dshield|ipv4|hash:net|20|Fri May 15 08:45:04 UTC 2015|[source](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules?r=31959)
emerging_block|ipv4|hash:net|1286|Fri May 15 00:36:08 UTC 2015|[source](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt?r=29824)
fullbogons|ipv4|hash:net|3624|Fri May 15 12:45:07 UTC 2015|[source](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt?r=4188)
infiltrated|ipv4|hash:ip|10372|Fri May 15 20:18:39 UTC 2015|[source](http://www.infiltrated.net/blacklisted?r=15279)
malc0de|ipv4|hash:ip|350|Fri May 15 12:45:04 UTC 2015|[source](http://malc0de.com/bl/IP_Blacklist.txt?r=1813)
malwaredomainlist|ipv4|hash:ip|1283|Wed May 13 19:15:52 UTC 2015|[source](http://www.malwaredomainlist.com/hostslist/ip.txt?r=24222)
openbl|ipv4|hash:ip|9806|Fri May 15 19:45:04 UTC 2015|[source](http://www.openbl.org/lists/base.txt?r=6636)
rosi_connect_proxies|ipv4|hash:ip|151|Fri May 15 20:19:27 UTC 2015|[source](http://tools.rosinstrument.com/proxy/plab100.xml?r=534)
rosi_web_proxies|ipv4|hash:ip|141|Fri May 15 20:19:06 UTC 2015|[source](http://tools.rosinstrument.com/proxy/l100.xml?r=32083)
spamhaus_drop|ipv4|hash:net|637|Fri May 15 12:27:07 UTC 2015|[source](http://www.spamhaus.org/drop/drop.txt?r=19040)
spamhaus_edrop|ipv4|hash:net|53|Fri May 15 12:27:09 UTC 2015|[source](http://www.spamhaus.org/drop/edrop.txt?r=8493)
stop_forum_spam_1h|ipv4|hash:ip|6298|Fri May 15 22:27:05 UTC 2015|[source](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
stop_forum_spam_30d|ipv4|hash:ip|94504|Fri May 15 08:45:21 UTC 2015|[source](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stop_forum_spam_7d|ipv4|hash:ip|30735|Fri May 15 18:27:16 UTC 2015|[source](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
tor|ipv4|hash:ip|6280|Fri May 15 10:54:06 UTC 2015|[source](http://rules.emergingthreats.net/blockrules/emerging-tor.rules?r=29059)
tor_servers|ipv4|hash:ip|6456|Fri May 15 22:00:20 UTC 2015|[source](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv?r=23334)
zeus|ipv4|hash:ip|261|Fri May 15 20:27:10 UTC 2015|[source](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist&r=28196)
