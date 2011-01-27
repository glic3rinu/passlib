from passlib.utils._slow_des_crypt import crypt as slow_crypt, CHARS
from passlib.utils import rng, getrandstr
from crypt import crypt as sys_crypt

SCHARS = "".join( chr(v) for v in xrange(1,255))

for c in xrange(200):
	size = rng.randint(1, 8)
	secret = getrandstr(rng, SCHARS, size)
	salt = getrandstr(rng, CHARS, 2)

	h1 = slow_crypt(secret, salt)
	h2 = sys_crypt(secret, salt)
	if h1 != h2:
		print "mismatch: %r %r => %r %r" % (secret, salt, h1, h2)
