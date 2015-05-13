# blocklist-ipsets

This repository includes a list of ipsets dynamically updated with
firehol's (https://github.com/ktsaou/firehol) `update-ipsets.sh`
script.

# Using these ipsets
Please be very careful what you choose to use and how you use it. If you blacklist traffic using these lists you may end up blocking your users, your customers, even yourself (!) from accessing your services.

1. Goto to the site of each list and read how each list is maintained. You are going to trust these guys for doing their job right.

2. Most sites have either a donation system or commercial lists of higher quality. Try to support them. 

3. Apply any blacklist at the internet side of your firewall.

4. Always have a whitelist too, containing the IP addresses or subnets you trust.

# Using them in FireHOL

## Adding them in your firehol.conf
TODO

## Updating them while the firewall is running


# Using them using plain iptables commands

## Creating the ipsets
TODO

## Updating the ipsets while the firewall is running
TODO

---

# List of ipsets included
