LSL-HMAC-SHA1-Fast
==================

Fast LSL HMAC-SHA1 with global pads.

This is a Linden Scripting Language HMAC-SHA1 hashing algorithm. I made it because the existing ones out there were too slow. This one is much faster because it heeds this advice given in RFC 2104:

"These intermediate results are stored and then used to initialize the IV of H each time that a message needs to be authenticated."
http://tools.ietf.org/html/rfc2104, p. 3

Use the first user function in the script to sign your requests. Add a communications event to talk to this script from your other scripts. This has been tested to work.
