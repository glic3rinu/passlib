"""

lanman

macintosh
D47F3AF827A48F7DFA4F2C1F12D68CD6 08460EB13C5CA0C4CA9516712F7FED95

ntlm

"""

from passlib.utils._slow_des_crypt import des_encrypt_rounds

secret = "macintosh"

s = secret.upper()[:14] + "\x00" * (14-len(secret))
sa, sb = s[:7], s[7:]

cc = 0
for c in reversed("KGS!@#$%"):
    cc <<= 8
    cc |= ord(c)

ka = 0
for c in reversed(sa):
    ka <<= 8
    ka |= (ord(c)<<1)

ct = des_encrypt_rounds(cc, 0, 25, ka)

out = ''
for i in xrange(8):
    out += '%02x' % ((ct>>(8*(7-i))) & 0xFF)

print out
