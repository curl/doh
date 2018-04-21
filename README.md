# doh

 A libcurl-using application that resolves a host name using DNS-over-HTTPS
 (DOH). Experiment area to work out code and logic for later inclusion into
 libcurl.

 This code uses POST requests unconditionally for this.

## Usage

    doh [host] [DOH URL]

If DOH URL is left out, the Cloudflare DOH server will be used.
