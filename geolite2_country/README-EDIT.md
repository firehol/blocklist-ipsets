# MaxMind Geolite2

[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases
are free IP geolocation databases comparable to, but less accurate than,
MaxMind’s GeoIP2 databases. GeoLite2 databases are updated on the first
Tuesday of each month.

The GeoLite2 databases are distributed under the [Creative Commons
Attribution-ShareAlike 3.0 Unported License](http://creativecommons.org/licenses/by-sa/3.0/).

The attribution requirement may be met by including the following in all advertising and documentation
mentioning features of or use of this database:

> This product includes GeoLite2 data created by MaxMind, available from [www.maxmind.com](http://www.maxmind.com).


## Country ipset

MaxMind distinguishes between several types of country data. The `country` is the country where the IP
address is located. The `registered_country` is the country in which the IP is registered.
These two may differ in some cases.

They also include a `represented_country` key for some records. This is used when the IP address belongs
to something like a military base. The `represented_country` is the country that the base represents.
This can be useful for managing content licensing, among other uses.

**In the ipsets generated, an IP subnet is added to all `country`, `registered_country` and `represented_country`
(of course only when these differ).**

More information [here](http://dev.maxmind.com/geoip/geoip2/whats-new-in-geoip2/).


## Continent ipsets

MaxMind provides the continent each IP subnet is located. Using this information we created the `geolite2/continent_*.netset` ipsets.


## Global providers

MaxMind provides two flags for each IP subnet.

- `A1` which stands for `is anonymous provider`
- `A2` which stands for `is satellite provider`

Using this information we created two additional ipsets: `geolite2/anonymous.netset` and `geolite2/satellite.netset`.


## Dynamic list of ipsets

