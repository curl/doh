# doh

 A libcurl-using application that resolves a host name using DNS-over-HTTPS
 (DoH).

 This code uses POST requests unconditionally for this.

## Usage

    doh [options] host [DoH URL]

If DoH URL is left out, the Cloudflare DoH server will be used. See also [list
of public
servers](https://github.com/curl/curl/wiki/DNS-over-HTTPS#publicly-available-servers)

Options:

- `-h` shows help output
- `-t` enables server test mode
- `-v` enables verbose mode
- `-k` enables insecure mode, skipping server certificate validation

## Examples

    $ doh www.example.com
    www.example.com from https://dns.cloudflare.com/dns-query
    TTL: 2612 seconds
    A: 93.184.216.34
    AAAA: 2606:2800:0220:0001:0248:1893:25c8:1946

    $ doh www.yahoo.com https://dns.google/dns-query
    www.yahoo.com from https://dns.google/dns-query
    TTL: 36 seconds
    A: 87.248.98.8
    A: 87.248.98.7
    AAAA: 2a00:1288:0110:001c:0000:0000:0000:0004
    AAAA: 2a00:1288:0110:001c:0000:0000:0000:0003
    CNAME: atsv2-fp.wg1.b.yahoo.com
    CNAME: atsv2-fp.wg1.b.yahoo.com
