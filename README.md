# doh

 A libcurl-using application that resolves a host name using DNS-over-HTTPS
 (DOH). Experiment area to work out code and logic for later inclusion into
 libcurl.

 This code uses POST requests unconditionally for this.

## Usage

    doh [options] host [DOH URL]

If DOH URL is left out, the Cloudflare DOH server will be used. See also [list
of public
servers](https://github.com/curl/curl/wiki/DNS-over-HTTPS#publicly-available-servers)

Options:

- -h shows help output
- -v enables verbose mode

## Examples

    $ doh www.example.com
    www.example.com from https://dns.cloudflare.com/.well-known/dns-query
    TTL: 2612 seconds
    A: 93.184.216.34
    AAAA: 2606:2800:0220:0001:0248:1893:25c8:1946
