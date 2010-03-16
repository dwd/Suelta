#
# Copyright 2004,2005 Dave Cridland <dave@cridland.net>
#
# This file forms part of the Infotrope Python Library.
#
# The Infotrope Python Library is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# The Infotrope Python Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with the Infotrope Python Library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#/usr/bin/env python

import random


have_saslprep = True
try:
	import infotrope.saslprep
except ImportError:
	have_saslprep = False

#print "SASL Module init"

mech = {}
mechmap = {}

session_passwords = {}

def hash(s):
	import hashlib
	s = s.lower()
	if s.startswith('sha-'):
		s = 'sha' + s[4:]
	if s in dir(hashlib):
		return hashlib.__getattribute__(s)
	return None

def hashes():
	import hashlib
	t = []
	if 'md5' in dir(hashlib):
		t = ['MD5']
	if 'md2' in dir(hashlib):
		t = ['MD2']
	hashes = ['SHA-'+h[3:] for h in dir(hashlib) if h.startswith('sha')]
	hashes.sort()
	return t + hashes

def register_mech(basename, basescore, impl, extra=None):
	n = 0
	for h in hashes():
		n += 1
		name = basename + h
		if extra is not None:
			name += extra
		mech[name] = impl
		mechmap[name] = basescore + n

class error:
	def __init__( self, sasl, txt, mech=None ):
		self.sasl = sasl
		self.txt = txt
		self.mech = mech

	def __str__( self ):
		if self.mech is None:
			return "SASL Error for " + str(self.sasl.uri) + ": " + self.txt
		else:
			return "SASL Error for " + str(self.sasl.uri) + ", mechanism " + self.mech.mechname + ": " + self.txt

class cancelled(error):
	def __init__( self, sasl, mech=None ):
		error.__init__( self, sasl, "User cancelled", mech )

_answers = {}

class sasl:
	def __init__( self, uri, min=0, service=None, callback=None, secquery=None, tls_active=None, defrealm=None ):
		self.defrealm = defrealm or uri.server
		self.uri = uri
		self.service = service or uri.scheme
		self.host = uri.server
		self.stash_id = None
		self.testkey = None
		self.user = None
		if self.uri.username is not None:
			self.reset_stash_id( self.uri.username )
		self.min = min - 1
		self.cb = callback
		self.try_username = self.user
		self.try_password = None
		self.transitioning = False
		self.tls_active = tls_active or self.def_tls_active
		self._secquery = secquery

	def secquery( self, mech, question ):
		if self._secquery is None:
			return False
		if question in _answers:
			return _answers[question]
		t = self._secquery( mech, question )
		if t:
			_answers[question] = t
		return t

	def def_tls_active( self ):
		return None

	def reset_stash_id( self, username ):
		if have_saslprep:
			username = infotrope.saslprep.saslprep( username )
		self.user = username
		self.uri.username = username
		self.try_username = self.user
		self.stash_id = self.user + '\0' + self.host + '\0' + self.service + '\0' + str(self.uri.port)
		self.testkey = self.stash_id.split('\0')

	def find_password( self, mech ):
		if self.try_password is not None:
			return self.try_password
		if self.testkey is None:
			return
		testkey = self.testkey[:]
		global session_passwords
		lockout = 1 # Below this level, we give up.
		if mechmap[mech.mechname] < 2:
			lockout = 2 # PLAIN et al.
		while len(testkey) >= lockout:
			tk = '\0'.join( testkey )
			if tk in session_passwords:
				return session_passwords[tk]
			testkey = testkey[:-1]

	def find_username( self ):
		if self.try_username is not None:
			return self.try_username

	def success( self, mech ):
		mech.preprep()
		if 'password' in mech.vals:
			global session_passwords
			testkey = self.testkey[:]
			while len(testkey):
				tk = '\0'.join( testkey )
				if tk in session_passwords:
					break
				session_passwords[tk] = mech.vals['password']
				testkey = testkey[:-1]
		mech.prep()
		mech.put_stash()

	def failure( self, mech ):
		mech.clear()
		self.testkey = self.testkey[:-1]
	
	def mechlist( self, mechs, force_plain=False ):
		if force_plain:
			return mech['PLAIN']( self, 'PLAIN' )
		if self.uri.username is not None:
			if self.uri.mechanism is None:
				requested_mechanism = '*'
			else:
				requested_mechanism = self.uri.mechanism
		else:
			if self.uri.mechanism is None:
				requested_mechanism = 'ANONYMOUS'
			else:
				requested_mechanism = self.uri.mechanism
		if requested_mechanism == '*' and self.uri.username == 'anonymous':
			requested_mechanism = 'ANONYMOUS'
		if requested_mechanism != '*':
			if requested_mechanism in mechs and requested_mechanism in mechmap: # Both ends have it.
				return mech[requested_mechanism]( self, requested_mechanism )
			if self.uri.mechanism=='VOODOO':
				if 'PLAIN' in mechs:
					return mech['VOODOO']( self, 'PLAIN' )
			return None
		bestmechv = self.min
		bestmech = None
		for c in mechs:
			if c in mechmap:
				if( mechmap[c] > bestmechv ):
					bestmech = c
					bestmechv = mechmap[c]
		if bestmech != None:
			bestmech = mech[bestmech]( self, bestmech )
		return bestmech

	def transition_needed( self, mech ):
		self.try_username = mech.vals['username']
		self.try_password = mech.vals['password']
		mech.put_stash()
		self.transitioning = True
	
	class saslmech:
		def __init__( self, sasl, mechname, v, use_stash = True ):
			self.mechname = mechname
			self.v = v
			self.sasl = sasl
			self.vals = {}
			self.use_stash = use_stash
			self.encoding = False
			if use_stash:
				self.getvals()

		def encode(self, s):
			return s
		def decode(self, s):
			return s

		def encode_flush(self):
			return ''
			
		def uri( self ):
			return self.sasl.uri
		
		def process( self, chatter ):
			raise "Pure virtual"

		def fulfill( self, vals ):
			self.vals.update( vals )
			
		def getvals( self ):
			self.vals = {}
			if not self.use_stash:
				return False
			if self.sasl.stash_id is not None:
				if self.sasl.stash_id in stash[0]:
					if stash[0][self.sasl.stash_id]['mech'] == self.mechname:
						self.vals.update( stash[0][self.sasl.stash_id]['vals'] )
			if self.sasl.user is not None:
				if not self.have_vals( ['username'] ):
					self.vals['username'] = self.sasl.user
			return None
			
		def put_stash( self ):
			if not self.use_stash:
				return
			if self.sasl.stash_id is not None:
				if self.sasl.stash_id not in stash[0]:
					stash[0][self.sasl.stash_id] = {}
				stash[0][self.sasl.stash_id]['vals'] = self.vals
				stash[0][self.sasl.stash_id]['mech'] = self.mechname
				if stash_file[0] is not None and stash_file[0]!='':
					import marshal
					fp = file( stash_file[0], "wb" )
					marshal.dump( stash[0], fp )

		def clear( self ):
			u = None
			if 'username' in self.vals:
				u = self.vals['username']
			self.vals = {}
			if u is not None:
				self.vals['username'] = u
			self.put_stash()
			self.vals = {}
			self.getvals()

		def name( self ):
			return self.mechname

		def okay( self ):
			return False

		def preprep( self ):
			if self.sasl.stash_id is None:
				if 'username' in self.vals:
					self.sasl.reset_stash_id( self.vals['username'] )
		def prep( self ):
			pass

		def getuser( self ):
			raise "Attempt to obtain username where none exists."

		def thing_vals( self, keys ):
			tmp = {}
			for x in keys:
				if x not in self.vals or self.vals[x] is None:
					if self.use_stash:
						if x=='username':
							v = self.sasl.find_username()
							if v is not None:
								self.sasl.reset_stash_id( v )
								self.vals[x] = v
								break
						elif x=='password':
							v = self.sasl.find_password( self )
							if v is not None:
								self.vals[x] = v
								break
					tmp[x] = None
			return tmp

		def have_vals( self, keys ):
			return 0==len(self.thing_vals(keys))

		def check_vals( self, keys ):
			tmp = self.thing_vals(keys)
			if len(tmp):
				self.sasl.cb( self, tmp )

try:
	import hmac

	class _cram_md5( sasl.saslmech ):
		def __init__( self, asasl, mechname ):
			sasl.saslmech.__init__( self, asasl, mechname, 2 )
			self.hash = hash(mechname[5:])
			if self.hash is None:
				raise cancelled( self.sasl, self )
			if self.sasl.tls_active() is None:
				if not self.sasl.secquery( self, "CRAM-MD5 is not very strong, and can be broken.\nShould I continue anyway? It is fairly safe to do so." ):
					raise cancelled( self.sasl, self )
	
		def process( self, chatter ):
			if chatter == None:
				return None
			self.check_vals( ['username','password'] )
			h = hmac.HMAC( key=self.vals["password"], digestmod=self.hash )
			h.update( chatter )
			tmp = self.vals["username"] + " " + h.hexdigest()
			return tmp
		
		def okay( self ):
			return True

		def prep( self ):
			if 'savepass' not in self.vals:
				if self.sasl.secquery( self, "Can I save this password in the clear?" ):
					self.vals['savepass'] = True
			if 'savepass' not in self.vals:
				del self.vals['password']
			return True
		
		def getuser( self ):
			return self.vals['username']
	
	register_mech('CRAM-', 20, _cram_md5)
	
	class _scram_hmac(sasl.saslmech):
		def __init__(self, sasl, mechname):
			sasl.saslmech.__init__(self, sasl, mechname, 0)
			self.cb = False
			if mechname[-5:] == "-PLUS":
				mechname = mechname[:-5]
				self.cb = True
			self.hashfn = hash(mechname[6:])
			if self.hashfn is None:
				raise cancelled(self.sasl, self)
			if self.sasl.tls_active() is None:
				if not self.sasl.secquery( self, "I have no encryption, however I am using SCRAM.\nAn attacker listening to the wire could see what you're doing,\nbut would find it difficult to get your password.\nShould I continue?" ):
					raise cancelled( self.sasl, self )
			self.step = 0
			self.rspauth = False
		
		def scram_parse(self, chatter):
			stuff = {}
			for k,v in [s.split('=',1) for s in chatter.split(',')]:
				stuff[k] = v
			return stuff
		
		def process_one(self, chatter):
			vitals = ['username']
			if 'SaltedPassword' not in self.vals:
				vitals.append('password')
			if 'Iterations' not in self.vals:
				vitals.append('password')
			self.check_vals(vitals)
			self.step = 1
			self.cnonce = str(random.random())[2:]
			self.soup = "n=" + self.vals['username'] + ",r=" + self.cnonce
			self.gs2header = ''
			cbdata = self.sasl.tls_active()
			if cbdata is not None and cbdata is not True:
				if self.cb:
					self.gs2header = 'p=tls-unique,,'
				else:
					self.gs2header = 'y,,'
			else:
				self.gs2header = 'n,,'
			return self.gs2header + self.soup

		def HMAC(self, k, s):
			return hmac.HMAC(key=k, msg=s, digestmod=self.hashfn).digest()
		
		def XOR(self, x, y):
			r = []
			for i in range(len(x)):
				r.append(chr(ord(x[i])^ord(y[i])))
			return ''.join(r)

		def Hi(self, s, salt, iters):
			ii = 1
			print `salt`,`s`
			p = s
			try:
				p = s.encode('utf-8')
			except:
				pass
			ui_1 = self.HMAC(p, salt + '\0\0\0\01')
			print `ui_1`
			ui = ui_1
			for i in range(iters - 1):
				ii += 1
				ui_1 = self.HMAC(p, ui_1)
				ui = self.XOR(ui, ui_1)
			print "\nHi(",`p`,`salt`,`iters`,")-->",iters, ii, "\n"
			return ui
		
		def H(self, s):
			return self.hashfn(s).digest()
		
		def base64(self, s):
			return ''.join(s.encode('base64').split('\n'))
			
		def process_two(self, chatter):
			self.step = 2
			self.soup += "," + chatter + ","
			data = self.scram_parse(chatter)
			self.nonce = data['r']
			self.salt = data['s'].decode('base64')
			self.iter = int(data['i'])
			if self.nonce[:len(self.cnonce)] != self.cnonce:
				raise cancelled(self.sasl, self)
			cbdata = self.sasl.tls_active()
			c = self.gs2header
			if cbdata is not None and cbdata is not True and self.cb:
				c += cbdata
			r = 'c=' + self.base64(c)
			r += ',r=' + self.nonce
			self.soup += r		
			if 'Iterations' in self.vals:
				if self.vals['Iterations'] != self.iter:
					if 'SaltedPassword' in self.vals:
						del self.vals['SaltedPassword']
			if 'Salt' in self.vals:
				if self.vals['Salt'] != self.salt:
					if 'SaltedPassword' in self.vals:
						del self.vals['SaltedPassword']
			self.vals['Iterations'] = self.iter
			self.vals['Salt'] = self.salt
			if 'SaltedPassword' not in self.vals:
				self.check_vals(['password'])
				self.vals['SaltedPassword'] = self.Hi(self.vals['password'], self.salt, self.iter)
			ClientKey = self.HMAC(self.vals['SaltedPassword'], "Client Key")
			StoredKey = self.H(ClientKey)
			print `self.soup`
			ClientSignature = self.HMAC(StoredKey, self.soup)
			ClientProof = self.XOR(ClientKey, ClientSignature)
			r += ',p=' + self.base64(ClientProof)
			ServerKey = self.HMAC(self.vals['SaltedPassword'], "Server Key")
			self.ServerSignature = self.HMAC(ServerKey, self.soup)
			return r
		
		def process_three(self, chatter):
			data = self.scram_parse(chatter)
			if data['v'].decode('base64') == self.ServerSignature:
				self.rspauth = True
		
		def process(self, chatter):
			if self.step == 0:
				return self.process_one(chatter)
			elif self.step == 1:
				return self.process_two(chatter)
			elif self.step == 2:
				return self.process_three(chatter)
		
		def okay( self ):
			return self.rspauth
		
		def prep( self ):
			if 'password' in self.vals:
				del self.vals['password']
		
		def getuser( self ):
			return self.vals['username']
			
	register_mech('SCRAM-', 60, _scram_hmac)
	register_mech('SCRAM-', 70, _scram_hmac, '-PLUS')

except ImportError:
	pass

class _anonymous(sasl.saslmech):
	def __init__( self, sasl, mechname ):
		sasl.saslmech.__init__( self, sasl, mechname, 0 )

	def getvals( self ):
		return {}

	def process( self, chatter ):
		return "Anonymous, Infotrope Python SASL"

	def okay( self ):
		return True

	def getuser( self ):
		return "anonymous"

mech['ANONYMOUS'] = _anonymous
mechmap['ANONYMOUS'] = 0

class _digest_md5(sasl.saslmech):
	enc_magic = "Digest session key to client-to-server signing key magic constant"
	dec_magic = "Digest session key to server-to-client signing key magic constant"
	def __init__( self, asasl, mechname ):
		sasl.saslmech.__init__( self, asasl, mechname, 3 )
		self.hashfn = hash(mechname[7:])
		if self.hashfn is None:
			raise cancelled(self.sasl, self)
		if self.sasl.tls_active() is None:
			if not self.sasl.secquery( self, "I have no encryption, however I am using DIGEST-MD5.\nAn attacker listening to the wire could see what you're doing,\nbut would find it difficult to get your password.\nShould I continue?" ):
				raise cancelled( self.sasl, self )
		self._rspauth_okay = False
		self._digest_uri = None
		self._a1 = None
		self._encbuf = ''
		self._enc_key = None
		self._enc_seq = 0
		self._max_buffer = 65536
		self._decbuf = ''
		self._dec_key = None
		self._dec_seq = 0
		self._a1 = None
		self._qops = ['auth']
		self._qop = 'auth'

	def encode(self, s):
		self._encbuf += s
		return ''
	
	def tobytes(self, l):
		s = ''
		s += chr(0xFF & (l >> 24))
		s += chr(0xFF & (l >> 16))
		s += chr(0xFF & (l >> 8))
		s += chr(0xFF & (l >> 0))
		return s

	def frombytes(self, s):
		return (ord(s[0]) << 24) + (ord(s[1]) << 16) + (ord(s[2]) << 8) + ord(s[3])

	def make_mac(self, seq, msg, key):
		mac = hmac.HMAC(key=key, digestmod=self.hashfn)
		seqnum = self.tobytes(seq)
		mac.update(seqnum)
		mac.update(msg)
		return mac.digest()[:10] + '\x00\x01' + seqnum

	def encode_flush(self):
		res = ''
		mbuf = self._max_buffer - 10 - 2 - 4 # From length of above.
		while self._encbuf:
			msg = self._encbuf[:mbuf]
			mac = self.make_mac(self._enc_seq, msg, self._enc_key)
			self._enc_seq += 1
			msg += mac
			res += self.tobytes(len(msg)) + msg
			self._encbuf = self._encbuf[mbuf:]
		return res

	def decode(self,s):
		self._decbuf += s
		ret = ''
		while len(self._decbuf) > 4:
			l = self.frombytes(self._decbuf)
			if len(self._decbuf) < (l + 4):
				return ret
			msg_mac = self._decbuf[4:4+l]
			self._decbuf = self._decbuf[4+l:]
			msg = msg_mac[:-16]
			if msg_mac[-16:] != self.make_mac(self._dec_seq, msg, self._dec_key):
				self._dec_seq = None
				return ret
			self._dec_seq += 1
			ret += msg
		return ret

	def decode_dmd5( self, stuff ):
		ret = {}
		var = ''
		val = ''
		in_var = True
		in_quotes = False
		new = False
		escaped = False
		for c in stuff:
			if in_var:
				if c.isspace():
					continue
				if c == '=':
					in_var = False
					new = True
				else:
					var += c
			else:
				if new:
					if c == '"':
						in_quotes = True
					else:
						val += c
					new = False
				elif in_quotes:
					if escaped:
						escaped = False
						val += c
					else:
						if c == '\\':
							escaped = True
						elif c == '"':
							in_quotes = False
						else:
							val += c
				else:
					if c == ',':
						if var:
							ret[var] = val
						var = ''
						val = ''
						in_var = True
					else:
						val += c
		if var:
			ret[var] = val
		return ret

	def quote( self, what ):
		return '"' + what.replace('\\','\\\\').replace( '"', '\\"' ) + '"'

	def response( self ):
		vitals = ['username']
		if not self.have_vals( ['key_hash'] ):
			vitals.append( 'password' )
		self.check_vals( vitals )
		resp = {}
		if 'auth-int' in self._qops:
			self._qop = 'auth-int'
		resp['qop'] = self._qop
		if 'realm' in self.vals:
			resp['realm'] = self.quote( self.vals['realm'] )
		resp['username'] = self.quote( self.vals['username'] )
		resp['nonce'] = self.quote( self.vals['nonce'] )
		if self.vals['nc']: # Reauth
			self.cnonce = self.vals['cnonce']
		else:
			self.cnonce = str(random.random())[2:]
		resp['cnonce'] = self.quote(self.cnonce)
		self.vals['nc'] += 1
		resp['nc'] = '%08x' % self.vals['nc']
		self._digest_uri = self.sasl.service + '/' + self.sasl.host
		resp['digest-uri'] = self.quote( self._digest_uri )
		a2 = 'AUTHENTICATE:%s' % ( self._digest_uri )
		if self._qop != 'auth':
			a2 += ":00000000000000000000000000000000"
			resp['maxbuf'] = str(2**24-1)
		resp['response'] = self.gen_hash( a2 )
		return ','.join( [ '='.join(x) for x in resp.items() ] )

	def gen_hash( self, a2 ):
		if not self.have_vals( ['key_hash'] ):
			key_hash = self.hashfn()
			kh = "%s:%s:%s" % ( self.vals['username'].encode('utf-8'), self.vals['realm'], self.vals['password'].encode('utf-8') )
			key_hash.update(kh)
			self.vals['key_hash'] = key_hash.digest()
		a1 = self.hashfn( self.vals['key_hash'] )
		a1h = ':%s:%s' % ( self.vals['nonce'], self.cnonce )
		a1.update( a1h )
		response = self.hashfn()
		self._a1 = a1.digest()
		rv = '%s:%s:%08x:%s:%s:%s' % (
			a1.hexdigest().lower(),
			self.vals['nonce'],
			self.vals['nc'],
			self.cnonce,
			self._qop,
			self.hashfn( a2 ).hexdigest().lower()
			)
		response.update( rv )
		return response.hexdigest().lower()

	def mutual_auth( self, cmp_hash ):
		a2 = ':' + self._digest_uri
		if self._qop != 'auth':
			a2 += ":00000000000000000000000000000000"
		if self.gen_hash( a2 )==cmp_hash:
			self._rspauth_okay = True

	def process( self, chatter=None ):
		if chatter is None:
			if self.have_vals( ['username','realm','nonce','key_hash','nc','cnonce','qops'] ):
				self._qops = self.vals['qops']
				return self.response()
			else:
				return None
		d = self.decode_dmd5( chatter )
		if 'rspauth' in d:
			self.mutual_auth( d['rspauth'] )
		else:
			if 'realm' not in d:
				d['realm'] = self.sasl.defrealm
			for x in ['nonce','realm']:
				if x in d:
					self.vals[x] = d[x]
			self.vals['nc'] = 0
			self._qops = ['auth']
			if 'qop' in d:
				self._qops = [x.strip() for x in d['qop'].split(',')]
			self.vals['qops'] = self._qops
			if 'maxbuf' in d:
				self._max_buffer = int(d['maxbuf'])
			return self.response()

	def okay( self ):
		if self._rspauth_okay and self._qop == 'auth-int':
			self._enc_key = self.hashfn( self._a1 + self.enc_magic ).digest()
			self._dec_key = self.hashfn( self._a1 + self.dec_magic ).digest()
			self.encoding = True
		return self._rspauth_okay

	def prep( self ):
		if 'password' in self.vals:
			del self.vals['password']
		self.vals['cnonce'] = self.cnonce

	def getuser( self ):
		return self.vals['username']
register_mech('DIGEST-', 30, _digest_md5)

class _plain(sasl.saslmech):
	def __init__( self, asasl, plainname ):
		sasl.saslmech.__init__( self, asasl, plainname, 1 )
		if self.sasl.tls_active() is None:
			if not self.sasl.secquery( self, "I need to use plaintext authentication,\nbut I have no encryption layer. This is bad, as it is easy\nto obtain your password, and impossible to prevent.\nDo you REALLY want me to continue?" ):
				raise cancelled( self.sasl, self )
		else:
			if not self.sasl.secquery( self, "I have encryption, but I need to use\nplaintext authentication. If the server has been hacked,\nI will give the attacker your password.\nThis is unlikely, but should I continue?" ):
				raise cancelled( self.sasl, self )
		self.check_vals( ['username','password'] )

	def process( self, chatter=None ):
		return '\0%s\0%s' % ( self.vals['username'], self.vals['password'] )

	def getuser( self ):
		return self.vals['username']

	def prep( self ):
		if 'savepass' not in self.vals:
			if self.sasl.secquery( self, "Can I save this password in the clear?" ):
				self.vals['savepass'] = True
		if 'savepass' not in self.vals:
			del self.vals['password']
		return True
		
	def okay( self ):
		return True
mech['PLAIN'] = _plain
mechmap['PLAIN'] = 1

stash = [{}]
stash_file = ['']

def set_stash_file( filename ):
	stash_file[0]=filename
	try:
		import marshal
		st = file( filename )
		stash[0] = marshal.load( st )
	except:
		stash[0] = {}
	return

