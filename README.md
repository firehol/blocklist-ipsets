> Due to the amount of data and the frequency of the updates on this repo,
> github has requested to limit the number of updates.
> The site [https://iplists.firehol.org](https://iplists.firehol.org) has direct links
> to all the files in this repo. **This repo is now updated once per day.**

---

### Contents

- [About this repo](#about-this-repo)

- [Using these ipsets](#using-these-ipsets)
 - [Which ones to use?](#which-ones-to-use)

 - [Why are open proxy lists included](#why-are-open-proxy-lists-included)
   
 - [Using them in FireHOL](#using-them-in-firehol)
    * [Adding the ipsets in your firehol.conf](#adding-the-ipsets-in-your-fireholconf)
    * [Updating the ipsets while the firewall is running](#updating-the-ipsets-while-the-firewall-is-running)
    
- [Dynamic List of ipsets included](#list-of-ipsets-included)

- [Comparison of ipsets](#comparison-of-ipsets)

---

# About this repo

This repository includes a list of ipsets dynamically updated with
[FireHOL](https://github.com/firehol/firehol)'s `update-ipsets.sh`
[documented in this wiki](https://github.com/firehol/blocklist-ipsets/wiki).

This repo is self maintained. It it updated automatically from the script via a cron job.

This repo has a site: [http://iplists.firehol.org](http://iplists.firehol.org).

## Why do we need blocklists?

As time passes and the internet matures in our life, cybercrime is becoming increasingly sophisticated.
Although there are many tools (detection of malware, viruses, intrusion detection and prevention systems,
etc) to help us isolate the bad guys, there are now a lot more than just such attacks.

What is more interesting is that the fraudsters or attackers in many cases are not going to do a direct
damage to you or your systems. They will use you and your systems to gain something else, possibly not
related or indirectly related to your business. Nowadays the attacks cannot be identified easily. They are
distributed and come to our systems from a vast amount of IPs around the world.

To get an idea, check for example the [XRumer](http://en.wikipedia.org/wiki/XRumer) software. This thing
mimics human behavior to post ads, it creates email accounts, responds to emails it receives, bypasses
captchas, it goes gently to stay unnoticed, etc.

To increase our effectiveness we need to complement our security solutions with our shared knowledge, our
shared experience in this fight.

Hopefully, there are many teams out there that do their best to identify the attacks and pinpoint the
attackers. These teams release blocklists. Blocklists of IPs (for use in firewalls), domains & URLs
(for use in proxies), etc.

What we are interested here is IPs.

Using IP blocklists at the internet side of your firewall is a key component of internet security. These
lists share key knowledge between us, allowing us to learn from each other and effectively isolate
fraudsters and attackers from our services.

I decided to upload these lists to a github repo because:

1. They are freely available on the internet. The intention of their creators is to help internet security.
 Keep in mind though that a few of these lists may have special licences attached. Before using them, please check their source site for any information regarding proper use.

2. Github provides (via `git pull`) a unified way of updating all the lists together.
 Pulling this repo regularly on your machines, you will update all the IP lists at once.

3. Github also provides a unified version control. Using it we can have a history of what each list has
done, which IPs or subnets were added and which were removed.

## DNSBLs

Check also another tool included in FireHOL v3+, called `dnsbl-ipset.sh`.

This tool is capable of creating an ipset based on your traffic by looking up information on DNSBLs and
scoring it according to your preferences.

More information [here](https://github.com/firehol/firehol/wiki/dnsbl-ipset.sh).


---

# Using these ipsets

Please be very careful what you choose to use and how you use it. If you blacklist traffic using these
lists you may end up blocking your users, your customers, even yourself (!) from accessing your services.

1. Go to to the site of each list and read how each list is maintained. You are going to trust these guys for doing their job right.

2. Most sites have either a donation system or commercial lists of higher quality. Try to support them. 

3. I have included the TOR network in these lists (`bm_tor`, `dm_tor`, `et_tor`). The TOR network is not necessarily bad and you should not block it if you want to allow your users be anonymous. I have included it because for certain cases, allowing an anonymity network might be a risky thing (such as eCommerce).

4. Apply any blacklist at the internet side of your firewall. Be very careful. The `bogons` and `fullbogons` lists contain private, unrouteable IPs that should not be routed on the internet. If you apply such a blocklist on your DMZ or LAN side, you will be blocked out of your firewall.

5. Always have a whitelist too, containing the IP addresses or subnets you trust. Try to build the rules in such a way that if an IP is in the whitelist, it should not be blocked by these blocklists.


## Which ones to use


### Level 1 - Basic

These are the ones I trust. **Level 1** provides basic security against the most well-known attackers, with the minimum of false positives.

1. **Abuse.ch** lists `feodo`, `palevo`, `sslbl`, `zeus`, `zeus_badips`
   
   These folks are doing a great job tracking crime ware. Their blocklists are very focused.
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

Of course, there are more lists included. You can check them and decide if they fit for your needs.

## Why are open proxy lists included

Of course, I haven't included them for you to use the open proxies. The port the proxy is listening, or the type of proxy, are not included (although most of them use the standard proxy ports and do serve web requests).

If you check the comparisons for the open proxy lists (`ri_connect_proxies`, `ri_web_proxies`, `xroxy`, `proxz`, `proxyrss`, etc)
you will find that they overlap to a great degree with other blocklists, like `blocklist_de`, `stopforumspam`, etc.

> This means the attackers also use open proxies to execute attacks.

So, if you are under attack, blocking the open proxies may help isolate a large part of the attack.

I don't suggest to permanently block IPs using the proxy lists. Their purpose of existence is questionable.
Their quality though may be acceptable, since lot of these sites advertise that they test open proxies before including them in their lists, so that there are no false positives, at least at the time they tested them.

---

## Using them in FireHOL

`update-ipsets.sh` itself does not alter your firewall. It can be used to update ipsets both on disk and in the kernel for any firewall solution you use.

The information below, shows you how to configure FireHOL to use the provides ipsets.


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

> You can add `update-ipsets.sh` to cron, to run every 10 mins. `update-ipsets.sh` is smart enough to download
> a list only when it needs to.

---

# List of ipsets included

The following list was automatically generated on Sun Feb  8 10:53:23 UTC 2026.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[bds_atif](http://iplists.firehol.org/?ipset=bds_atif)|Artillery Threat Intelligence Feed and Banlist Feed|ipv4 hash:ip|2454 unique IPs|updated every 1 day  from [this link](https://www.binarydefense.com/banlist.txt)
[bitcoin_nodes](http://iplists.firehol.org/?ipset=bitcoin_nodes)|[BitNodes](https://getaddr.bitnodes.io/) Bitcoin connected nodes, globally.|ipv4 hash:ip|7196 unique IPs|updated every 10 mins  from [this link](https://getaddr.bitnodes.io/api/v1/snapshots/latest/)
[bitcoin_nodes_1d](http://iplists.firehol.org/?ipset=bitcoin_nodes_1d)|[BitNodes](https://getaddr.bitnodes.io/) Bitcoin connected nodes, globally.|ipv4 hash:ip|7998 unique IPs|updated every 10 mins  from [this link](https://getaddr.bitnodes.io/api/v1/snapshots/latest/)
[bitcoin_nodes_30d](http://iplists.firehol.org/?ipset=bitcoin_nodes_30d)|[BitNodes](https://getaddr.bitnodes.io/) Bitcoin connected nodes, globally.|ipv4 hash:ip|15789 unique IPs|updated every 10 mins  from [this link](https://getaddr.bitnodes.io/api/v1/snapshots/latest/)
[bitcoin_nodes_7d](http://iplists.firehol.org/?ipset=bitcoin_nodes_7d)|[BitNodes](https://getaddr.bitnodes.io/) Bitcoin connected nodes, globally.|ipv4 hash:ip|9777 unique IPs|updated every 10 mins  from [this link](https://getaddr.bitnodes.io/api/v1/snapshots/latest/)
[blocklist_de](http://iplists.firehol.org/?ipset=blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours|ipv4 hash:ip|25144 unique IPs|updated every 15 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](http://iplists.firehol.org/?ipset=blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|10393 unique IPs|updated every 15 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](http://iplists.firehol.org/?ipset=blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = it has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3335 unique IPs|updated every 15 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](http://iplists.firehol.org/?ipset=blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomla, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2262 unique IPs|updated every 15 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](http://iplists.firehol.org/?ipset=blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|160 unique IPs|updated every 15 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](http://iplists.firehol.org/?ipset=blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|3046 unique IPs|updated every 15 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](http://iplists.firehol.org/?ipset=blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|12413 unique IPs|updated every 15 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](http://iplists.firehol.org/?ipset=blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from infiltrated.net|ipv4 hash:ip|68 unique IPs|updated every 15 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](http://iplists.firehol.org/?ipset=blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|6737 unique IPs|updated every 15 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](http://iplists.firehol.org/?ipset=blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|286 unique IPs|updated every 15 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[blocklist_net_ua](http://iplists.firehol.org/?ipset=blocklist_net_ua)|[blocklist.net.ua](https://blocklist.net.ua) The BlockList project was created to become protection against negative influence of the harmful and potentially dangerous events on the Internet. First of all this service will help internet and hosting providers to protect subscribers sites from being hacked. BlockList will help to stop receiving a large amount of spam from dubious SMTP relays or from attempts of brute force passwords to servers and network equipment.|ipv4 hash:ip|77678 unique IPs|updated every 10 mins  from [this link](https://blocklist.net.ua/blocklist.csv)
bm_tor|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|disabled|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](http://iplists.firehol.org/?ipset=bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day 
[botscout](http://iplists.firehol.org/?ipset=botscout)|[BotScout](http://botscout.com/) helps prevent automated web scripts, known as bots, from registering on forums, polluting databases, spreading spam, and abusing forms on web sites. They do this by tracking the names, IPs, and email addresses that bots use and logging them as unique signatures for future reference. They also provide a simple yet powerful API that you can use to test forms when they're submitted on your site. This list is composed of the most recently-caught bots.|ipv4 hash:ip|30 unique IPs|updated every 30 mins  from [this link](http://botscout.com/last_caught_cache.htm)
[botscout_1d](http://iplists.firehol.org/?ipset=botscout_1d)|[BotScout](http://botscout.com/) helps prevent automated web scripts, known as bots, from registering on forums, polluting databases, spreading spam, and abusing forms on web sites. They do this by tracking the names, IPs, and email addresses that bots use and logging them as unique signatures for future reference. They also provide a simple yet powerful API that you can use to test forms when they're submitted on your site. This list is composed of the most recently-caught bots.|ipv4 hash:ip|618 unique IPs|updated every 30 mins  from [this link](http://botscout.com/last_caught_cache.htm)
[botscout_30d](http://iplists.firehol.org/?ipset=botscout_30d)|[BotScout](http://botscout.com/) helps prevent automated web scripts, known as bots, from registering on forums, polluting databases, spreading spam, and abusing forms on web sites. They do this by tracking the names, IPs, and email addresses that bots use and logging them as unique signatures for future reference. They also provide a simple yet powerful API that you can use to test forms when they're submitted on your site. This list is composed of the most recently-caught bots.|ipv4 hash:ip|7234 unique IPs|updated every 30 mins  from [this link](http://botscout.com/last_caught_cache.htm)
[botscout_7d](http://iplists.firehol.org/?ipset=botscout_7d)|[BotScout](http://botscout.com/) helps prevent automated web scripts, known as bots, from registering on forums, polluting databases, spreading spam, and abusing forms on web sites. They do this by tracking the names, IPs, and email addresses that bots use and logging them as unique signatures for future reference. They also provide a simple yet powerful API that you can use to test forms when they're submitted on your site. This list is composed of the most recently-caught bots.|ipv4 hash:ip|2376 unique IPs|updated every 30 mins  from [this link](http://botscout.com/last_caught_cache.htm)
botvrij_dst|[botvrij.eu](http://www.botvrij.eu/) Indicators of Compromise (IOCS) about malicious destination IPs, gathered via open source information feeds (blog pages and PDF documents) and then consolidated into different datasets. To ensure the quality of the data all entries older than approx. 6 months are removed.|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.botvrij.eu/data/ioclist.ip-dst.raw)
botvrij_src|[botvrij.eu](http://www.botvrij.eu/) Indicators of Compromise (IOCS) about malicious source IPs, gathered via open source information feeds (blog pages and PDF documents) and then consolidated into different datasets. To ensure the quality of the data all entries older than approx. 6 months are removed.|ipv4 hash:ip|disabled|updated every 1 day  from [this link](http://www.botvrij.eu/data/ioclist.ip-src.raw)
[bruteforceblocker](http://iplists.firehol.org/?ipset=bruteforceblocker)|[danger.rulez.sk bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|437 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](http://iplists.firehol.org/?ipset=ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|15000 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cidr_report_bogons](http://iplists.firehol.org/?ipset=cidr_report_bogons)|Unallocated (Free) Address Space, generated on a daily basis using the IANA registry files, the Regional Internet Registry stats files and the Regional Internet Registry whois data.|ipv4 hash:net|18 subnets, 588514808 unique IPs|updated every 1 day  from [this link](http://www.cidr-report.org/bogons/freespace-prefix.txt)
[cleantalk](http://iplists.firehol.org/?ipset=cleantalk)|[CleanTalk](https://cleantalk.org/) Today's HTTP Spammers (includes: cleantalk_new cleantalk_updated)|ipv4 hash:ip|494 unique IPs|updated every 1 min 
[cleantalk_1d](http://iplists.firehol.org/?ipset=cleantalk_1d)|[CleanTalk](https://cleantalk.org/) Today's HTTP Spammers (includes: cleantalk_new_1d cleantalk_updated_1d)|ipv4 hash:ip|1900 unique IPs|updated every 1 min 
[cleantalk_30d](http://iplists.firehol.org/?ipset=cleantalk_30d)|[CleanTalk](https://cleantalk.org/) Today's HTTP Spammers (includes: cleantalk_new_30d cleantalk_updated_30d)|ipv4 hash:ip|37919 unique IPs|updated every 1 min 
[cleantalk_7d](http://iplists.firehol.org/?ipset=cleantalk_7d)|[CleanTalk](https://cleantalk.org/) Today's HTTP Spammers (includes: cleantalk_new_7d cleantalk_updated_7d)|ipv4 hash:ip|9233 unique IPs|updated every 1 min 
[cleantalk_new](http://iplists.firehol.org/?ipset=cleantalk_new)|[CleanTalk](https://cleantalk.org/) Recent HTTP Spammers|ipv4 hash:ip|250 unique IPs|updated every 15 mins  from [this link](https://cleantalk.org/blacklists/submited_today)
[cleantalk_new_1d](http://iplists.firehol.org/?ipset=cleantalk_new_1d)|[CleanTalk](https://cleantalk.org/) Recent HTTP Spammers|ipv4 hash:ip|754 unique IPs|updated every 15 mins  from [this link](https://cleantalk.org/blacklists/submited_today)
[cleantalk_new_30d](http://iplists.firehol.org/?ipset=cleantalk_new_30d)|[CleanTalk](https://cleantalk.org/) Recent HTTP Spammers|ipv4 hash:ip|15416 unique IPs|updated every 15 mins  from [this link](https://cleantalk.org/blacklists/submited_today)
[cleantalk_new_7d](http://iplists.firehol.org/?ipset=cleantalk_new_7d)|[CleanTalk](https://cleantalk.org/) Recent HTTP Spammers|ipv4 hash:ip|3989 unique IPs|updated every 15 mins  from [this link](https://cleantalk.org/blacklists/submited_today)
[cleantalk_top20](http://iplists.firehol.org/?ipset=cleantalk_top20)|[CleanTalk](https://cleantalk.org/) Top 20 HTTP Spammers|ipv4 hash:ip|20 unique IPs|updated every 1 day  from [this link](https://cleantalk.org/blacklists/top20)
[cleantalk_updated](http://iplists.firehol.org/?ipset=cleantalk_updated)|[CleanTalk](https://cleantalk.org/) Recurring HTTP Spammers|ipv4 hash:ip|250 unique IPs|updated every 15 mins  from [this link](https://cleantalk.org/blacklists/updated_today)
[cleantalk_updated_1d](http://iplists.firehol.org/?ipset=cleantalk_updated_1d)|[CleanTalk](https://cleantalk.org/) Recurring HTTP Spammers|ipv4 hash:ip|1278 unique IPs|updated every 15 mins  from [this link](https://cleantalk.org/blacklists/updated_today)
[cleantalk_updated_30d](http://iplists.firehol.org/?ipset=cleantalk_updated_30d)|[CleanTalk](https://cleantalk.org/) Recurring HTTP Spammers|ipv4 hash:ip|28579 unique IPs|updated every 15 mins  from [this link](https://cleantalk.org/blacklists/updated_today)
[cleantalk_updated_7d](http://iplists.firehol.org/?ipset=cleantalk_updated_7d)|[CleanTalk](https://cleantalk.org/) Recurring HTTP Spammers|ipv4 hash:ip|6171 unique IPs|updated every 15 mins  from [this link](https://cleantalk.org/blacklists/updated_today)
[cta_cryptowall](http://iplists.firehol.org/?ipset=cta_cryptowall)|[Cyber Threat Alliance](http://www.cyberthreatalliance.org/cryptowall-dashboard.html)  CryptoWall is one of the most lucrative and broad-reaching ransomware campaigns affecting Internet users today. Sharing intelligence and analysis resources, the CTA profiled the latest version of CryptoWall, which impacted hundreds of thousands of users, resulting in over US $325 million in damages worldwide.|ipv4 hash:ip|1360 unique IPs|updated every 1 day  from [this link](https://public.tableau.com/views/CTAOnlineViz/DashboardData.csv?:embed=y&:showVizHome=no&:showTabs=y&:display_count=y&:display_static_image=y&:bootstrapWhenNotified=true)
[cybercrime](http://iplists.firehol.org/?ipset=cybercrime)|[CyberCrime](http://cybercrime-tracker.net/) A project tracking Command and Control.|ipv4 hash:ip|216 unique IPs|updated every 12 hours  from [this link](http://cybercrime-tracker.net/fuckerz.php)
[darklist_de](http://iplists.firehol.org/?ipset=darklist_de)|[darklist.de](http://www.darklist.de/) ssh fail2ban reporting|ipv4 hash:net|6008 subnets, 274857 unique IPs|updated every 1 day  from [this link](http://www.darklist.de/raw.php)
[dataplane_dnsrd](http://iplists.firehol.org/?ipset=dataplane_dnsrd)|[DataPlane.org](https://dataplane.org/) IP addresses that have been identified as sending recursive DNS queries to a remote host. This report lists addresses that may be cataloging open DNS resolvers or evaluating cache entries.|ipv4 hash:ip|26192 unique IPs|updated every 1 hour 
[dataplane_dnsrdany](http://iplists.firehol.org/?ipset=dataplane_dnsrdany)|[DataPlane.org](https://dataplane.org/) IP addresses that have been identified as sending recursive DNS IN ANY queries to a remote host. This report lists addresses that may be cataloging open DNS resolvers for the purpose of later using them to facilitate DNS amplification and reflection attacks.|ipv4 hash:ip|19357 unique IPs|updated every 1 hour 
[dataplane_dnsversion](http://iplists.firehol.org/?ipset=dataplane_dnsversion)|[DataPlane.org](https://dataplane.org/) IP addresses that have been identified as sending DNS CH TXT VERSION.BIND queries to a remote host. This report lists addresses that may be cataloging DNS software.|ipv4 hash:ip|6306 unique IPs|updated every 1 hour 
[dataplane_sipinvitation](http://iplists.firehol.org/?ipset=dataplane_sipinvitation)|[DataPlane.org](https://dataplane.org/) IP addresses that have been seen initiating a SIP INVITE operation to a remote host. This report lists hosts that are suspicious of more than just port scanning.  These hosts may be SIP client cataloging or conducting various forms of telephony abuse.|ipv4 hash:ip|32 unique IPs|updated every 1 hour 
[dataplane_sipquery](http://iplists.firehol.org/?ipset=dataplane_sipquery)|[DataPlane.org](https://dataplane.org/) IP addresses that has been seen initiating a SIP OPTIONS query to a remote host. This report lists hosts that are suspicious of more than just port scanning. These hosts may be SIP server cataloging or conducting various forms of telephony abuse.|ipv4 hash:ip|5100 unique IPs|updated every 1 hour 
[dataplane_sipregistration](http://iplists.firehol.org/?ipset=dataplane_sipregistration)|[DataPlane.org](https://dataplane.org/) IP addresses that have been seen initiating a SIP REGISTER operation to a remote host. This report lists hosts that are suspicious of more than just port scanning.  These hosts may be SIP client cataloging or conducting various forms of telephony abuse.|ipv4 hash:ip|459 unique IPs|updated every 1 hour 
[dataplane_sshclient](http://iplists.firehol.org/?ipset=dataplane_sshclient)|[DataPlane.org](https://dataplane.org/) IP addresses that has been seen initiating an SSH connection to a remote host. This report lists hosts that are suspicious of more than just port scanning.  These hosts may be SSH server cataloging or conducting authentication attack attempts.|ipv4 hash:ip|27651 unique IPs|updated every 1 hour 
[dataplane_sshpwauth](http://iplists.firehol.org/?ipset=dataplane_sshpwauth)|[DataPlane.org](https://dataplane.org/) IP addresses that has been seen attempting to remotely login to a host using SSH password authentication. This report lists hosts that are highly suspicious and are likely conducting malicious SSH password authentication attacks.|ipv4 hash:ip|19314 unique IPs|updated every 1 hour 
[dataplane_vncrfb](http://iplists.firehol.org/?ipset=dataplane_vncrfb)|[DataPlane.org](https://dataplane.org/) IP addresses that have been seen initiating a VNC remote frame buffer (RFB) session to a remote host. This report lists hosts that are suspicious of more than just port scanning. These hosts may be VNC server cataloging or conducting various forms of remote access abuse.|ipv4 hash:ip|2508 unique IPs|updated every 1 hour 
[dm_tor](http://iplists.firehol.org/?ipset=dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR nodes|ipv4 hash:ip|7327 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dronebl_anonymizers](http://iplists.firehol.org/?ipset=dronebl_anonymizers)|[DroneBL.org](https://dronebl.org) List of open proxies. It includes IPs which DroneBL categorizes as SOCKS proxies (8), HTTP proxies (9), web page proxies (11), WinGate proxies (14), proxy chains (10).|ipv4 hash:net|1255781 subnets, 1358979 unique IPs|updated every 1 min 
[dronebl_auto_botnets](http://iplists.firehol.org/?ipset=dronebl_auto_botnets)|[DroneBL.org](https://dronebl.org) IPs of automatically detected botnets. It includes IPs for which DroneBL responds with 17.|ipv4 hash:net|7227 subnets, 7336 unique IPs|updated every 1 min 
[dronebl_autorooting_worms](http://iplists.firehol.org/?ipset=dronebl_autorooting_worms)|[DroneBL.org](https://dronebl.org) IPs of autorooting worms. It includes IPs for which DroneBL responds with 16. These are usually SSH bruteforce attacks.|ipv4 hash:net|36 subnets, 36 unique IPs|updated every 1 min 
[dronebl_compromised](http://iplists.firehol.org/?ipset=dronebl_compromised)|[DroneBL.org](https://dronebl.org) IPs of compromised routers / gateways. It includes IPs for which DroneBL responds with 15 (BOPM detected).|ipv4 hash:net|46268 subnets, 47712 unique IPs|updated every 1 min 
[dronebl_ddos_drones](http://iplists.firehol.org/?ipset=dronebl_ddos_drones)|[DroneBL.org](https://dronebl.org) IPs of DDoS drones. It includes IPs for which DroneBL responds with 7.|ipv4 hash:net|7298 subnets, 7454 unique IPs|updated every 1 min 
[dronebl_dns_mx_on_irc](http://iplists.firehol.org/?ipset=dronebl_dns_mx_on_irc)|[DroneBL.org](https://dronebl.org) List of IPs of DNS / MX hostname detected on IRC. It includes IPs for which DroneBL responds with 18.|ipv4 hash:net|16 subnets, 16 unique IPs|updated every 1 min 
[dronebl_irc_drones](http://iplists.firehol.org/?ipset=dronebl_irc_drones)|[DroneBL.org](https://dronebl.org) List of IRC spam drones (litmus/sdbot/fyle). It includes IPs for which DroneBL responds with 3.|ipv4 hash:net|836301 subnets, 1005894 unique IPs|updated every 1 min 
[dronebl_unknown](http://iplists.firehol.org/?ipset=dronebl_unknown)|[DroneBL.org](https://dronebl.org) List of IPs of uncategorized threats. It includes IPs for which DroneBL responds with 255.|ipv4 hash:net|16 subnets, 16 unique IPs|updated every 1 min 
[dronebl_worms_bots](http://iplists.firehol.org/?ipset=dronebl_worms_bots)|[DroneBL.org](https://dronebl.org) IPs of unknown worms or spambots. It includes IPs for which DroneBL responds with 6|ipv4 hash:net|432587 subnets, 444102 unique IPs|updated every 1 min 
[dshield](http://iplists.firehol.org/?ipset=dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 10 mins  from [this link](https://feeds.dshield.org/block.txt)
[dshield_1d](http://iplists.firehol.org/?ipset=dshield_1d)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days|ipv4 hash:net|28 subnets, 7168 unique IPs|updated every 10 mins  from [this link](https://feeds.dshield.org/block.txt)
[dshield_30d](http://iplists.firehol.org/?ipset=dshield_30d)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days|ipv4 hash:net|69 subnets, 19200 unique IPs|updated every 10 mins  from [this link](https://feeds.dshield.org/block.txt)
[dshield_7d](http://iplists.firehol.org/?ipset=dshield_7d)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days|ipv4 hash:net|41 subnets, 10752 unique IPs|updated every 10 mins  from [this link](https://feeds.dshield.org/block.txt)
[et_block](http://iplists.firehol.org/?ipset=et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1422 subnets, 14858754 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_compromised](http://iplists.firehol.org/?ipset=et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost)|ipv4 hash:ip|437 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_dshield](http://iplists.firehol.org/?ipset=et_dshield)|[EmergingThreats.net](http://www.emergingthreats.net/) dshield blocklist|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DSHIELD.rules)
[et_spamhaus](http://iplists.firehol.org/?ipset=et_spamhaus)|[EmergingThreats.net](http://www.emergingthreats.net/) spamhaus blocklist|ipv4 hash:net|1404 subnets, 14854656 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules)
[et_tor](http://iplists.firehol.org/?ipset=et_tor)|[EmergingThreats.net TOR list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|7290 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](http://iplists.firehol.org/?ipset=feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud|ipv4 hash:ip|0 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt)
[feodo_badips](http://iplists.firehol.org/?ipset=feodo_badips)|[Abuse.ch Feodo tracker BadIPs](https://feodotracker.abuse.ch) The Feodo Tracker Feodo BadIP Blocklist only contains IP addresses (IPv4) used as C&C communication channel by the Feodo Trojan version B. These IP addresses are usually servers rented by cybercriminals directly and used for the exclusive purpose of hosting a Feodo C&C server. Hence you should expect no legit traffic to those IP addresses. The site highly recommends you to block/drop any traffic towards any Feodo C&C using the Feodo BadIP Blocklist. Please consider that this blocklist only contains IP addresses used by version B of the Feodo Trojan. C&C communication channels used by version A, version C and version D are not covered by this blocklist.|ipv4 hash:ip|3 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/downloads/ipblocklist.txt)
[firehol_abusers_1d](http://iplists.firehol.org/?ipset=firehol_abusers_1d)|An ipset made from blocklists that track abusers in the last 24 hours. (includes: botscout_1d cleantalk_new_1d cleantalk_updated_1d php_commenters_1d php_dictionary_1d php_harvesters_1d php_spammers_1d stopforumspam_1d)|ipv4 hash:net|5541 subnets, 5653 unique IPs|updated every 1 min 
[firehol_abusers_30d](http://iplists.firehol.org/?ipset=firehol_abusers_30d)|An ipset made from blocklists that track abusers in the last 30 days. (includes: cleantalk_new_30d cleantalk_updated_30d php_commenters_30d php_dictionary_30d php_harvesters_30d php_spammers_30d stopforumspam sblam)|ipv4 hash:net|168742 subnets, 179573 unique IPs|updated every 1 min 
[firehol_anonymous](http://iplists.firehol.org/?ipset=firehol_anonymous)|An ipset that includes all the anonymizing IPs of the world. (includes: anonymous dm_tor firehol_proxies tor_exits)|ipv4 hash:net|1888734 subnets, 2289911 unique IPs|updated every 1 min 
[firehol_level1](http://iplists.firehol.org/?ipset=firehol_level1)|A firewall blacklist composed from IP lists, providing maximum protection with minimum false positives. Suitable for basic protection on all internet facing servers, routers and firewalls. (includes: dshield feodo fullbogons spamhaus_drop spamhaus_edrop)|ipv4 hash:net|4497 subnets, 611654720 unique IPs|updated every 1 min 
[firehol_level2](http://iplists.firehol.org/?ipset=firehol_level2)|An ipset made from blocklists that track attacks, during about the last 48 hours. (includes: blocklist_de dshield_1d greensnow)|ipv4 hash:net|17237 subnets, 33610 unique IPs|updated every 1 min 
[firehol_level3](http://iplists.firehol.org/?ipset=firehol_level3)|An ipset made from blocklists that track attacks, spyware, viruses. It includes IPs than have been reported or detected in the last 30 days. (includes: bruteforceblocker ciarmy dshield_30d myip vxvault)|ipv4 hash:net|12150 subnets, 32601 unique IPs|updated every 1 min 
[firehol_level4](http://iplists.firehol.org/?ipset=firehol_level4)|An ipset made from blocklists that track attacks, but may include a large number of false positives. (includes: blocklist_net_ua botscout_30d cybercrime iblocklist_hijacked iblocklist_spyware iblocklist_webexploit)|ipv4 hash:net|77136 subnets, 9174259 unique IPs|updated every 1 min 
[firehol_proxies](http://iplists.firehol.org/?ipset=firehol_proxies)|An ipset made from all sources that track open proxies. It includes IPs reported or detected in the last 30 days. (includes: iblocklist_proxies ip2proxy_px1lite socks_proxy_30d sslproxies_30d)|ipv4 hash:net|1882749 subnets, 2276675 unique IPs|updated every 1 min 
[firehol_webclient](http://iplists.firehol.org/?ipset=firehol_webclient)|An IP blacklist made from blocklists that track IPs that a web client should never talk to. This list is to be used on top of firehol_level1. (includes: cybercrime)|ipv4 hash:net|216 subnets, 216 unique IPs|updated every 1 min 
[firehol_webserver](http://iplists.firehol.org/?ipset=firehol_webserver)|A web server IP blacklist made from blocklists that track IPs that should never be used by your web users. (This list includes IPs that are servers hosting malware, bots, etc or users having a long criminal history. This list is to be used on top of firehol_level1, firehol_level2, firehol_level3 and possibly firehol_proxies or firehol_anonymous). (includes: myip stopforumspam_toxic)|ipv4 hash:net|810 subnets, 123037 unique IPs|updated every 1 min 
[fullbogons](http://iplists.firehol.org/?ipset=fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user|ipv4 hash:net|2888 subnets, 596538176 unique IPs|updated every 1 day 
geolite2_asn|[MaxMind GeoLite2 ASN](https://dev.maxmind.com/geoip/geoip2/geolite2/)|ipv4 hash:net|disabled|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN-CSV.zip)
[geolite2_country](https://github.com/firehol/blocklist-ipsets/tree/master/geolite2_country)|[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases are free IP geolocation databases comparable to, but less accurate than, MaxMind’s GeoIP2 databases. They include IPs per country, IPs per continent, IPs used by anonymous services (VPNs, Proxies, etc) and Satellite Providers.|ipv4 hash:net|All the world|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip)
gofferje_sip|[Stefan Gofferje](http://stefan.gofferje.net/it-stuff/sipfraud/sip-attacker-blacklist) A personal blacklist of networks and IPs of SIP attackers. To end up here, the IP or network must have been the origin of considerable and repeated attacks on my PBX and additionally, the ISP didn't react to any complaint. Note from the author: I don't give any guarantees of accuracy, completeness or even usability! USE AT YOUR OWN RISK! Also note that I block complete countries, namely China, Korea and Palestine with blocklists from ipdeny.com, so some attackers will never even get the chance to get noticed by me to be put on this blacklist. I also don't accept any liabilities related to this blocklist. If you're an ISP and don't like your IPs being listed here, too bad! You should have done something about your customers' behavior and reacted to my complaints. This blocklist is nothing but an expression of my personal opinion and exercising my right of free speech.|ipv4 hash:net|disabled|updated every 6 hours  from [this link](http://stefan.gofferje.net/sipblocklist.zone)
[gpf_comics](http://iplists.firehol.org/?ipset=gpf_comics)|The GPF DNS Block List is a list of IP addresses on the Internet that have attacked the [GPF Comics](http://www.gpf-comics.com/) family of Web sites. IPs on this block list have been banned from accessing all of our servers because they were caught in the act of spamming, attempting to exploit our scripts, scanning for vulnerabilities, or consuming resources to the detriment of our human visitors.|ipv4 hash:ip|2606 unique IPs|updated every 1 day  from [this link](https://www.gpf-comics.com/dnsbl/export.php)
[graphiclineweb](http://iplists.firehol.org/?ipset=graphiclineweb)|[GraphiclineWeb](https://graphiclineweb.wordpress.com/tech-notes/ip-blacklist/) The IP’s, Hosts and Domains listed in this table are banned universally from accessing websites controlled by the maintainer. Some form of bad activity has been seen from the addresses listed. Bad activity includes: unwanted spiders, rule breakers, comment spammers, trackback spammers, spambots, hacker bots, registration bots and other scripting attackers, harvesters, nuisance spiders, spy bots and organizations spying on websites for commercial reasons.|ipv4 hash:net|2579 subnets, 330527 unique IPs|updated every 1 day  from [this link](https://graphiclineweb.wordpress.com/tech-notes/ip-blacklist/)
[greensnow](http://iplists.firehol.org/?ipset=greensnow)|[GreenSnow](https://greensnow.co/) is a team harvesting a large number of IPs from different computers located around the world. GreenSnow is comparable with SpamHaus.org for attacks of any kind except for spam. Their list is updated automatically and you can withdraw at any time your IP address if it has been listed. Attacks / bruteforce that are monitored are: Scan Port, FTP, POP3, mod_security, IMAP, SMTP, SSH, cPanel, etc.|ipv4 hash:ip|5105 unique IPs|updated every 30 mins  from [this link](http://blocklist.greensnow.co/greensnow.txt)
[iblocklist_abuse_palevo](http://iplists.firehol.org/?ipset=iblocklist_abuse_palevo)|palevotracker.abuse.ch IP blocklist.|ipv4 hash:net|12 subnets, 12 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=erqajhwrxiuvjxqrrwfj&fileformat=p2p&archiveformat=gz)
[iblocklist_abuse_spyeye](http://iplists.firehol.org/?ipset=iblocklist_abuse_spyeye)|spyeyetracker.abuse.ch IP blocklist.|ipv4 hash:net|83 subnets, 84 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=zvjxsfuvdhoxktpeiokq&fileformat=p2p&archiveformat=gz)
[iblocklist_abuse_zeus](http://iplists.firehol.org/?ipset=iblocklist_abuse_zeus)|zeustracker.abuse.ch IP blocklist that contains IP addresses which are currently beeing tracked on the abuse.ch ZeuS Tracker.|ipv4 hash:net|209 subnets, 212 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ynkdjqsjyfmilsgbogqf&fileformat=p2p&archiveformat=gz)
[iblocklist_ads](http://iplists.firehol.org/?ipset=iblocklist_ads)|Advertising trackers and a short list of bad/intrusive porn sites.|ipv4 hash:net|3385 subnets, 888189 unique IPs|updated every 12 hours 
[iblocklist_bogons](http://iplists.firehol.org/?ipset=iblocklist_bogons)|Unallocated address space.|ipv4 hash:net|2692 subnets, 645673639 unique IPs|updated every 12 hours 
[iblocklist_ciarmy_malicious](http://iplists.firehol.org/?ipset=iblocklist_ciarmy_malicious)|ciarmy.com IP blocklist. Based on information from a network of Sentinel devices deployed around the world, they compile a list of known bad IP addresses. Sentinel devices are uniquely positioned to pick up traffic from bad guys without requiring any type of signature-based or rate-based identification. If an IP is identified in this way by a significant number of Sentinels, the IP is malicious and should be blocked.|ipv4 hash:net|12430 subnets, 15000 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=npkuuhuxcsllnhoamkvm&fileformat=p2p&archiveformat=gz)
[iblocklist_cidr_report_bogons](http://iplists.firehol.org/?ipset=iblocklist_cidr_report_bogons)|cidr-report.org IP list of Unallocated address space.|ipv4 hash:net|18 subnets, 588514808 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=lujdnbasfaaixitgmxpp&fileformat=p2p&archiveformat=gz)
[iblocklist_cruzit_web_attacks](http://iplists.firehol.org/?ipset=iblocklist_cruzit_web_attacks)|CruzIT IP list with individual IP addresses of compromised machines scanning for vulnerabilities and DDOS attacks.|ipv4 hash:net|14096 subnets, 14397 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=czvaehmjpsnwwttrdoyl&fileformat=p2p&archiveformat=gz)
[iblocklist_dshield](http://iplists.firehol.org/?ipset=iblocklist_dshield)|known Hackers and such people.|ipv4 hash:net|16 subnets, 2566 unique IPs|updated every 12 hours 
[iblocklist_edu](http://iplists.firehol.org/?ipset=iblocklist_edu)|IPs used by Educational Institutions.|ipv4 hash:net|43893 subnets, 227798708 unique IPs|updated every 12 hours 
[iblocklist_exclusions](http://iplists.firehol.org/?ipset=iblocklist_exclusions)|Exclusions.|ipv4 hash:net|313 subnets, 7488 unique IPs|updated every 12 hours 
[iblocklist_fornonlancomputers](http://iplists.firehol.org/?ipset=iblocklist_fornonlancomputers)|IP blocklist for non-LAN computers.|ipv4 hash:net|4 subnets, 302055424 unique IPs|updated every 12 hours 
[iblocklist_forumspam](http://iplists.firehol.org/?ipset=iblocklist_forumspam)|Forum spam.|ipv4 hash:net|455 subnets, 479 unique IPs|updated every 12 hours 
[iblocklist_hijacked](http://iplists.firehol.org/?ipset=iblocklist_hijacked)|Hijacked IP-Blocks. Contains hijacked IP-Blocks and known IP-Blocks that are used to deliver Spam. This list is a combination of lists with hijacked IP-Blocks. Hijacked IP space are IP blocks that are being used without permission by organizations that have no relation to original organization (or its legal successor) that received the IP block. In essence it's stealing of somebody else's IP resources.|ipv4 hash:net|512 subnets, 8736512 unique IPs|updated every 12 hours 
[iblocklist_iana_multicast](http://iplists.firehol.org/?ipset=iblocklist_iana_multicast)|IANA Multicast IPs.|ipv4 hash:net|1 subnets, 268435456 unique IPs|updated every 12 hours 
[iblocklist_iana_private](http://iplists.firehol.org/?ipset=iblocklist_iana_private)|IANA Private IPs.|ipv4 hash:net|58 subnets, 51643646 unique IPs|updated every 12 hours 
[iblocklist_iana_reserved](http://iplists.firehol.org/?ipset=iblocklist_iana_reserved)|IANA Reserved IPs.|ipv4 hash:net|1 subnets, 536870912 unique IPs|updated every 12 hours 
[iblocklist_isp_aol](http://iplists.firehol.org/?ipset=iblocklist_isp_aol)|AOL IPs.|ipv4 hash:net|16 subnets, 6627584 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=toboaiysofkflwgrttmb&fileformat=p2p&archiveformat=gz)
[iblocklist_isp_att](http://iplists.firehol.org/?ipset=iblocklist_isp_att)|AT&T IPs.|ipv4 hash:net|35 subnets, 55845128 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=grbtkzijgrowvobvessf&fileformat=p2p&archiveformat=gz)
[iblocklist_isp_cablevision](http://iplists.firehol.org/?ipset=iblocklist_isp_cablevision)|Cablevision IPs.|ipv4 hash:net|11 subnets, 1787136 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=dwwbsmzirrykdlvpqozb&fileformat=p2p&archiveformat=gz)
[iblocklist_isp_charter](http://iplists.firehol.org/?ipset=iblocklist_isp_charter)|Charter IPs.|ipv4 hash:net|21 subnets, 6138112 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=htnzojgossawhpkbulqw&fileformat=p2p&archiveformat=gz)
[iblocklist_isp_comcast](http://iplists.firehol.org/?ipset=iblocklist_isp_comcast)|Comcast IPs.|ipv4 hash:net|33 subnets, 45121536 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=rsgyxvuklicibautguia&fileformat=p2p&archiveformat=gz)
[iblocklist_isp_embarq](http://iplists.firehol.org/?ipset=iblocklist_isp_embarq)|Embarq IPs.|ipv4 hash:net|14 subnets, 2703360 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=twdblifaysaqtypevvdp&fileformat=p2p&archiveformat=gz)
[iblocklist_isp_qwest](http://iplists.firehol.org/?ipset=iblocklist_isp_qwest)|Qwest IPs.|ipv4 hash:net|73 subnets, 15777552 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=jezlifrpefawuoawnfez&fileformat=p2p&archiveformat=gz)
[iblocklist_isp_sprint](http://iplists.firehol.org/?ipset=iblocklist_isp_sprint)|Sprint IPs.|ipv4 hash:net|73 subnets, 6310570 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=hngtqrhhuadlceqxbrob&fileformat=p2p&archiveformat=gz)
[iblocklist_isp_suddenlink](http://iplists.firehol.org/?ipset=iblocklist_isp_suddenlink)|Suddenlink IPs.|ipv4 hash:net|3 subnets, 458752 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=psaoblrwylfrdsspfuiq&fileformat=p2p&archiveformat=gz)
[iblocklist_isp_twc](http://iplists.firehol.org/?ipset=iblocklist_isp_twc)|Time Warner Cable IPs.|ipv4 hash:net|56 subnets, 15015936 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=aqtsnttnqmcucwrjmohd&fileformat=p2p&archiveformat=gz)
[iblocklist_isp_verizon](http://iplists.firehol.org/?ipset=iblocklist_isp_verizon)|Verizon IPs.|ipv4 hash:net|22 subnets, 18087936 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=cdmdbprvldivlqsaqjol&fileformat=p2p&archiveformat=gz)
[iblocklist_level1](http://iplists.firehol.org/?ipset=iblocklist_level1)|Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.|ipv4 hash:net|235635 subnets, 721933914 unique IPs|updated every 12 hours 
[iblocklist_level2](http://iplists.firehol.org/?ipset=iblocklist_level2)|Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.|ipv4 hash:net|78368 subnets, 337917571 unique IPs|updated every 12 hours 
[iblocklist_level3](http://iplists.firehol.org/?ipset=iblocklist_level3)|Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.|ipv4 hash:net|18864 subnets, 137080799 unique IPs|updated every 12 hours 
[iblocklist_malc0de](http://iplists.firehol.org/?ipset=iblocklist_malc0de)|malc0de.com IP blocklist. Addresses that have been identified distributing malware during the past 30 days.|ipv4 hash:net|21 subnets, 21 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=pbqcylkejciyhmwttify&fileformat=p2p&archiveformat=gz)
[iblocklist_onion_router](http://iplists.firehol.org/?ipset=iblocklist_onion_router)|The Onion Router IP addresses.|ipv4 hash:net|906 subnets, 1345 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=togdoptykrlolpddwbvz&fileformat=p2p&archiveformat=gz)
[iblocklist_org_activision](http://iplists.firehol.org/?ipset=iblocklist_org_activision)|Activision IPs.|ipv4 hash:net|49 subnets, 4902 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=gfnxlhxsijzrcuxwzebb&fileformat=p2p&archiveformat=gz)
[iblocklist_org_apple](http://iplists.firehol.org/?ipset=iblocklist_org_apple)|Apple IPs.|ipv4 hash:net|1 subnets, 16777216 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=aphcqvpxuqgrkgufjruj&fileformat=p2p&archiveformat=gz)
[iblocklist_org_blizzard](http://iplists.firehol.org/?ipset=iblocklist_org_blizzard)|Blizzard IPs.|ipv4 hash:net|8 subnets, 16795139 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=ercbntshuthyykfkmhxc&fileformat=p2p&archiveformat=gz)
[iblocklist_org_crowd_control](http://iplists.firehol.org/?ipset=iblocklist_org_crowd_control)|Crowd Control Productions IPs.|ipv4 hash:net|2 subnets, 768 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=eveiyhgmusglurfmjyag&fileformat=p2p&archiveformat=gz)
[iblocklist_org_electronic_arts](http://iplists.firehol.org/?ipset=iblocklist_org_electronic_arts)|Electronic Arts IPs.|ipv4 hash:net|42 subnets, 69720 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=ejqebpcdmffinaetsvxj&fileformat=p2p&archiveformat=gz)
[iblocklist_org_joost](http://iplists.firehol.org/?ipset=iblocklist_org_joost)|Joost IPs.|ipv4 hash:net|4 subnets, 16779456 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=alxugfmeszbhpxqfdits&fileformat=p2p&archiveformat=gz)
[iblocklist_org_linden_lab](http://iplists.firehol.org/?ipset=iblocklist_org_linden_lab)|Linden Lab IPs.|ipv4 hash:net|11 subnets, 23600 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=qnjdimxnaupjmpqolxcv&fileformat=p2p&archiveformat=gz)
[iblocklist_org_logmein](http://iplists.firehol.org/?ipset=iblocklist_org_logmein)|LogMeIn IPs.|ipv4 hash:net|13 subnets, 16781568 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=tgbankumtwtrzllndbmb&fileformat=p2p&archiveformat=gz)
[iblocklist_org_microsoft](http://iplists.firehol.org/?ipset=iblocklist_org_microsoft)|Microsoft IP ranges.|ipv4 hash:net|901 subnets, 1848599 unique IPs|updated every 12 hours 
[iblocklist_org_ncsoft](http://iplists.firehol.org/?ipset=iblocklist_org_ncsoft)|NCsoft IPs.|ipv4 hash:net|5 subnets, 12560 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=mwjuwmebrnzyyxpbezxu&fileformat=p2p&archiveformat=gz)
[iblocklist_org_nintendo](http://iplists.firehol.org/?ipset=iblocklist_org_nintendo)|Nintendo IPs.|ipv4 hash:net|45 subnets, 3927 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=pevkykuhgaegqyayzbnr&fileformat=p2p&archiveformat=gz)
[iblocklist_org_pandora](http://iplists.firehol.org/?ipset=iblocklist_org_pandora)|Pandora IPs.|ipv4 hash:net|1 subnets, 2048 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=aevzidimyvwybzkletsg&fileformat=p2p&archiveformat=gz)
[iblocklist_org_pirate_bay](http://iplists.firehol.org/?ipset=iblocklist_org_pirate_bay)|The Pirate Bay IPs.|ipv4 hash:net|5 subnets, 323 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=nzldzlpkgrcncdomnttb&fileformat=p2p&archiveformat=gz)
[iblocklist_org_punkbuster](http://iplists.firehol.org/?ipset=iblocklist_org_punkbuster)|Punkbuster IPs.|ipv4 hash:net|1 subnets, 1 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=zvwwndvzulqcltsicwdg&fileformat=p2p&archiveformat=gz)
[iblocklist_org_riot_games](http://iplists.firehol.org/?ipset=iblocklist_org_riot_games)|Riot Games IPs.|ipv4 hash:net|6 subnets, 1792 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=sdlvfabdjvrdttfjotcy&fileformat=p2p&archiveformat=gz)
[iblocklist_org_sony_online](http://iplists.firehol.org/?ipset=iblocklist_org_sony_online)|Sony Online Entertainment IPs.|ipv4 hash:net|7 subnets, 24616 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=tukpvrvlubsputmkmiwg&fileformat=p2p&archiveformat=gz)
[iblocklist_org_square_enix](http://iplists.firehol.org/?ipset=iblocklist_org_square_enix)|Square Enix IPs.|ipv4 hash:net|2 subnets, 4112 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=odyaqontcydnodrlyina&fileformat=p2p&archiveformat=gz)
[iblocklist_org_steam](http://iplists.firehol.org/?ipset=iblocklist_org_steam)|Steam IPs.|ipv4 hash:net|53 subnets, 596448 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=cnxkgiklecdaihzukrud&fileformat=p2p&archiveformat=gz)
[iblocklist_org_ubisoft](http://iplists.firehol.org/?ipset=iblocklist_org_ubisoft)|Ubisoft IPs.|ipv4 hash:net|10 subnets, 5308 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=etmcrglomupyxtaebzht&fileformat=p2p&archiveformat=gz)
[iblocklist_org_xfire](http://iplists.firehol.org/?ipset=iblocklist_org_xfire)|XFire IPs.|ipv4 hash:net|3 subnets, 3328 unique IPs|updated every 1 day  from [this link](http://list.iblocklist.com/?list=ppqqnyihmcrryraaqsjo&fileformat=p2p&archiveformat=gz)
[iblocklist_pedophiles](http://iplists.firehol.org/?ipset=iblocklist_pedophiles)|IP ranges of people who we have found to be sharing child pornography in the p2p community.|ipv4 hash:net|29188 subnets, 847889 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=dufcxgnbjsdwmwctgfuj&fileformat=p2p&archiveformat=gz)
[iblocklist_proxies](http://iplists.firehol.org/?ipset=iblocklist_proxies)|Open Proxies IPs list (without TOR)|ipv4 hash:ip|672 unique IPs|updated every 12 hours 
[iblocklist_rangetest](http://iplists.firehol.org/?ipset=iblocklist_rangetest)|Suspicious IPs that are under investigation.|ipv4 hash:net|576 subnets, 4280758 unique IPs|updated every 12 hours 
[iblocklist_spamhaus_drop](http://iplists.firehol.org/?ipset=iblocklist_spamhaus_drop)|Spamhaus.org DROP (Don't Route Or Peer) list.|ipv4 hash:net|900 subnets, 17338368 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=zbdlwrqkabxbcppvrnos&fileformat=p2p&archiveformat=gz)
[iblocklist_spider](http://iplists.firehol.org/?ipset=iblocklist_spider)|IP list intended to be used by webmasters to block hostile spiders from their web sites.|ipv4 hash:net|773 subnets, 846788 unique IPs|updated every 12 hours 
[iblocklist_spyware](http://iplists.firehol.org/?ipset=iblocklist_spyware)|Known malicious SPYWARE and ADWARE IP Address ranges. It is compiled from various sources, including other available spyware blacklists, HOSTS files, from research found at many of the top anti-spyware forums, logs of spyware victims, etc.|ipv4 hash:net|3360 subnets, 339050 unique IPs|updated every 12 hours 
[iblocklist_webexploit](http://iplists.firehol.org/?ipset=iblocklist_webexploit)|Web server hack and exploit attempts. IP addresses related to current web server hack and exploit attempts that have been logged or can be found in and cross referenced with other related IP databases. Malicious and other non search engine bots will also be listed here, along with anything found that can have a negative impact on a website or webserver such as proxies being used for negative SEO hijacks, unauthorised site mirroring, harvesting, scraping, snooping and data mining / spy bot / security & copyright enforcement companies that target and continuosly scan webservers.|ipv4 hash:ip|15382 unique IPs|updated every 12 hours 
[iblocklist_yoyo_adservers](http://iplists.firehol.org/?ipset=iblocklist_yoyo_adservers)|pgl.yoyo.org ad servers|ipv4 hash:net|7535 subnets, 8912 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=zhogegszwduurnvsyhdf&fileformat=p2p&archiveformat=gz)
[ip2location_country](https://github.com/ktsaou/blocklist-ipsets/tree/master/ip2location_country)|[IP2Location.com](http://lite.ip2location.com/database-ip-country) geolocation database|ipv4 hash:net|All the world|updated every 1 day  from [this link](http://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.CSV.ZIP)
[ip2location_country_eh](http://iplists.firehol.org/?ipset=ip2location_country_eh)|Western Sahara (EH) -- [IP2Location.com](http://lite.ip2location.com/database-ip-country)|ipv4 hash:net|1 subnets, 256 unique IPs|updated every 1 day  from [this link](http://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.CSV.ZIP)
[ip2proxy_px1lite](http://iplists.firehol.org/?ipset=ip2proxy_px1lite)|[IP2Location.com](https://lite.ip2location.com/database/px1-ip-country) IP2Proxy LITE IP-COUNTRY Database contains IP addresses which are used as public proxies. The LITE edition is a free version of database that is limited to public proxies IP address.|ipv4 hash:net|1881055 subnets, 2274891 unique IPs|updated every 1 day 
[ipdeny_country](https://github.com/firehol/blocklist-ipsets/tree/master/ipdeny_country)|[IPDeny.com](http://www.ipdeny.com/) geolocation database|ipv4 hash:net|All the world|updated every 1 day  from [this link](http://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz)
[myip](http://iplists.firehol.org/?ipset=myip)|[myip.ms](http://www.myip.ms/info/about) IPs identified as web bots in the last 10 days, using several sites that require human action|ipv4 hash:ip|820 unique IPs|updated every 1 day  from [this link](http://www.myip.ms/files/blacklist/csf/latest_blacklist.txt)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) bad web hosts (this list is composed using an RSS feed)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](http://iplists.firehol.org/?ipset=php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed)|ipv4 hash:ip|49 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_commenters_1d](http://iplists.firehol.org/?ipset=php_commenters_1d)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed)|ipv4 hash:ip|91 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_commenters_30d](http://iplists.firehol.org/?ipset=php_commenters_30d)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed)|ipv4 hash:ip|1222 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_commenters_7d](http://iplists.firehol.org/?ipset=php_commenters_7d)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) comment spammers (this list is composed using an RSS feed)|ipv4 hash:ip|341 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](http://iplists.firehol.org/?ipset=php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed)|ipv4 hash:ip|47 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_dictionary_1d](http://iplists.firehol.org/?ipset=php_dictionary_1d)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed)|ipv4 hash:ip|47 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_dictionary_30d](http://iplists.firehol.org/?ipset=php_dictionary_30d)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed)|ipv4 hash:ip|924 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_dictionary_7d](http://iplists.firehol.org/?ipset=php_dictionary_7d)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed)|ipv4 hash:ip|278 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](http://iplists.firehol.org/?ipset=php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed)|ipv4 hash:ip|50 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_harvesters_1d](http://iplists.firehol.org/?ipset=php_harvesters_1d)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed)|ipv4 hash:ip|50 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_harvesters_30d](http://iplists.firehol.org/?ipset=php_harvesters_30d)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_harvesters_7d](http://iplists.firehol.org/?ipset=php_harvesters_7d)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed)|ipv4 hash:ip|91 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](http://iplists.firehol.org/?ipset=php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed)|ipv4 hash:ip|47 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[php_spammers_1d](http://iplists.firehol.org/?ipset=php_spammers_1d)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed)|ipv4 hash:ip|47 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[php_spammers_30d](http://iplists.firehol.org/?ipset=php_spammers_30d)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed)|ipv4 hash:ip|1115 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[php_spammers_7d](http://iplists.firehol.org/?ipset=php_spammers_7d)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed)|ipv4 hash:ip|289 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
proxyrss|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|disabled|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
ri_connect_proxies|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
ri_web_proxies|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed)|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[sblam](http://iplists.firehol.org/?ipset=sblam)|[sblam.com](http://sblam.com) IPs used by web form spammers, during the last month|ipv4 hash:ip|1248 unique IPs|updated every 1 day  from [this link](http://sblam.com/blacklist.txt)
[socks_proxy](http://iplists.firehol.org/?ipset=socks_proxy)|[socks-proxy.net](http://www.socks-proxy.net/) open SOCKS proxies|ipv4 hash:ip|302 unique IPs|updated every 10 mins  from [this link](http://www.socks-proxy.net/)
[socks_proxy_1d](http://iplists.firehol.org/?ipset=socks_proxy_1d)|[socks-proxy.net](http://www.socks-proxy.net/) open SOCKS proxies|ipv4 hash:ip|1435 unique IPs|updated every 10 mins  from [this link](http://www.socks-proxy.net/)
[socks_proxy_30d](http://iplists.firehol.org/?ipset=socks_proxy_30d)|[socks-proxy.net](http://www.socks-proxy.net/) open SOCKS proxies|ipv4 hash:ip|2574 unique IPs|updated every 10 mins  from [this link](http://www.socks-proxy.net/)
[socks_proxy_7d](http://iplists.firehol.org/?ipset=socks_proxy_7d)|[socks-proxy.net](http://www.socks-proxy.net/) open SOCKS proxies|ipv4 hash:ip|1987 unique IPs|updated every 10 mins  from [this link](http://www.socks-proxy.net/)
sorbs_anonymizers|[Sorbs.net](https://www.sorbs.net/) List of open HTTP and SOCKS proxies.|ipv4 hash:net|disabled|
sorbs_block|[Sorbs.net](https://www.sorbs.net/) List of hosts demanding that they never be tested by SORBS.|ipv4 hash:net|disabled|
sorbs_escalations|[Sorbs.net](https://www.sorbs.net/) Netblocks of spam supporting service providers, including those who provide websites, DNS or drop boxes for a spammer. Spam supporters are added on a 'third strike and you are out' basis, where the third spam will cause the supporter to be added to the list.|ipv4 hash:net|disabled|
sorbs_new_spam|[Sorbs.net](https://www.sorbs.net/) List of hosts that have been noted as sending spam/UCE/UBE within the last 48 hours|ipv4 hash:net|disabled|
sorbs_noserver|[Sorbs.net](https://www.sorbs.net/) IP addresses and netblocks of where system administrators and ISPs owning the network have indicated that servers should not be present.|ipv4 hash:net|disabled|
sorbs_recent_spam|[Sorbs.net](https://www.sorbs.net/) List of hosts that have been noted as sending spam/UCE/UBE within the last 28 days (includes sorbs_new_spam)|ipv4 hash:net|disabled|
sorbs_smtp|[Sorbs.net](https://www.sorbs.net/) List of SMTP Open Relays.|ipv4 hash:net|disabled|
sorbs_web|[Sorbs.net](https://www.sorbs.net/) List of IPs which have spammer abusable vulnerabilities (e.g. FormMail scripts)|ipv4 hash:net|disabled|
sorbs_zombie|[Sorbs.net](https://www.sorbs.net/) List of networks hijacked from their original owners, some of which have already used for spamming.|ipv4 hash:net|disabled|
[spamhaus_drop](http://iplists.firehol.org/?ipset=spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globally)|ipv4 hash:net|1404 subnets, 14854656 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](http://iplists.firehol.org/?ipset=spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP)|ipv4 hash:net|336 subnets, 731392 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslproxies](http://iplists.firehol.org/?ipset=sslproxies)|[SSLProxies.org](http://www.sslproxies.org/) open SSL proxies|ipv4 hash:ip|102 unique IPs|updated every 10 mins  from [this link](http://www.sslproxies.org/)
[sslproxies_1d](http://iplists.firehol.org/?ipset=sslproxies_1d)|[SSLProxies.org](http://www.sslproxies.org/) open SSL proxies|ipv4 hash:ip|218 unique IPs|updated every 10 mins  from [this link](http://www.sslproxies.org/)
[sslproxies_30d](http://iplists.firehol.org/?ipset=sslproxies_30d)|[SSLProxies.org](http://www.sslproxies.org/) open SSL proxies|ipv4 hash:ip|2134 unique IPs|updated every 10 mins  from [this link](http://www.sslproxies.org/)
[sslproxies_7d](http://iplists.firehol.org/?ipset=sslproxies_7d)|[SSLProxies.org](http://www.sslproxies.org/) open SSL proxies|ipv4 hash:ip|839 unique IPs|updated every 10 mins  from [this link](http://www.sslproxies.org/)
[stopforumspam](http://iplists.firehol.org/?ipset=stopforumspam)|[StopForumSpam.com](http://www.stopforumspam.com) Banned IPs used by forum spammers|ipv4 hash:ip|137556 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/bannedips.zip)
[stopforumspam_180d](http://iplists.firehol.org/?ipset=stopforumspam_180d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 180 days)|ipv4 hash:ip|279478 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_180.zip)
[stopforumspam_1d](http://iplists.firehol.org/?ipset=stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours|ipv4 hash:ip|3027 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](http://iplists.firehol.org/?ipset=stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|50742 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_365d](http://iplists.firehol.org/?ipset=stopforumspam_365d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 365 days)|ipv4 hash:ip|550426 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_365.zip)
[stopforumspam_7d](http://iplists.firehol.org/?ipset=stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|14730 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[stopforumspam_90d](http://iplists.firehol.org/?ipset=stopforumspam_90d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 90 days)|ipv4 hash:ip|137435 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_90.zip)
[stopforumspam_toxic](http://iplists.firehol.org/?ipset=stopforumspam_toxic)|[StopForumSpam.com](http://www.stopforumspam.com) Networks that have large amounts of spambots and are flagged as toxic. Toxic IP ranges are infrequently changed.|ipv4 hash:net|53 subnets, 122220 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/toxic_ip_cidr.txt)
[tor_exits](http://iplists.firehol.org/?ipset=tor_exits)|[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)|ipv4 hash:ip|1343 unique IPs|updated every 5 mins  from [this link](https://check.torproject.org/exit-addresses)
[tor_exits_1d](http://iplists.firehol.org/?ipset=tor_exits_1d)|[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)|ipv4 hash:ip|1349 unique IPs|updated every 5 mins  from [this link](https://check.torproject.org/exit-addresses)
[tor_exits_30d](http://iplists.firehol.org/?ipset=tor_exits_30d)|[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)|ipv4 hash:ip|1520 unique IPs|updated every 5 mins  from [this link](https://check.torproject.org/exit-addresses)
[tor_exits_7d](http://iplists.firehol.org/?ipset=tor_exits_7d)|[TorProject.org](https://www.torproject.org) list of all current TOR exit points (TorDNSEL)|ipv4 hash:ip|1383 unique IPs|updated every 5 mins  from [this link](https://check.torproject.org/exit-addresses)
urandomusto_dns|IP Feed about dns, crawled from several sources, including several twitter accounts.|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://urandom.us.to/report.php?ip=&info=&tag=dns&out=txt&submit=go)
urandomusto_ftp|IP Feed about ftp, crawled from several sources, including several twitter accounts.|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://urandom.us.to/report.php?ip=&info=&tag=ftp&out=txt&submit=go)
urandomusto_http|IP Feed about http, crawled from several sources, including several twitter accounts.|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://urandom.us.to/report.php?ip=&info=&tag=http&out=txt&submit=go)
urandomusto_mailer|IP Feed about mailer, crawled from several sources, including several twitter accounts.|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://urandom.us.to/report.php?ip=&info=&tag=mailer&out=txt&submit=go)
urandomusto_malware|IP Feed about malware, crawled from several sources, including several twitter accounts.|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://urandom.us.to/report.php?ip=&info=&tag=malware&out=txt&submit=go)
urandomusto_ntp|IP Feed about ntp, crawled from several sources, including several twitter accounts.|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://urandom.us.to/report.php?ip=&info=&tag=ntp&out=txt&submit=go)
urandomusto_rdp|IP Feed about rdp, crawled from several sources, including several twitter accounts.|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://urandom.us.to/report.php?ip=&info=&tag=rdp&out=txt&submit=go)
urandomusto_smb|IP Feed about smb, crawled from several sources, including several twitter accounts.|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://urandom.us.to/report.php?ip=&info=&tag=smb&out=txt&submit=go)
urandomusto_spam|IP Feed about spam, crawled from several sources, including several twitter accounts.|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://urandom.us.to/report.php?ip=&info=&tag=spam&out=txt&submit=go)
urandomusto_ssh|IP Feed about ssh, crawled from several sources, including several twitter accounts.|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://urandom.us.to/report.php?ip=&info=&tag=ssh&out=txt&submit=go)
urandomusto_telnet|IP Feed about telnet, crawled from several sources, including several twitter accounts.|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://urandom.us.to/report.php?ip=&info=&tag=telnet&out=txt&submit=go)
urandomusto_unspecified|IP Feed about unspecified, crawled from several sources, including several twitter accounts.|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://urandom.us.to/report.php?ip=&info=&tag=unspecified&out=txt&submit=go)
urandomusto_vnc|IP Feed about vnc, crawled from several sources, including several twitter accounts.|ipv4 hash:ip|disabled|updated every 1 hour  from [this link](http://urandom.us.to/report.php?ip=&info=&tag=vnc&out=txt&submit=go)
[vxvault](http://iplists.firehol.org/?ipset=vxvault)|[VxVault](http://vxvault.net) The latest 100 additions of VxVault.|ipv4 hash:ip|64 unique IPs|updated every 12 hours  from [this link](http://vxvault.net/ViriList.php?s=0&m=100)
[yoyo_adservers](http://iplists.firehol.org/?ipset=yoyo_adservers)|[Yoyo.org](http://pgl.yoyo.org/adservers/) IPs of ad servers|ipv4 hash:ip|8912 unique IPs|updated every 12 hours  from [this link](http://pgl.yoyo.org/adservers/iplist.php?ipformat=plain&showintro=0&mimetype=plaintext)
zeus|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives.|ipv4 hash:ip|disabled|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
zeus_badips|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist.|ipv4 hash:ip|disabled|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)
