# gather-keepass-http-creds
This is a simple tool to gather credentials from keepass-http. The connection to the keepass-http
local server is encrypted, however this key is stored in the browsers local-storage which is
readable by any user. This program reads the key (currently only from the "chromeIPass" extension)
and makes a request to the server encrypted with this key, then decrypts the response and prints it.

# Usage
    python get_keypass.py <url>
