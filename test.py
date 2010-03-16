import sasl
import socket

# Walkthrough - and test - for Suelta.
# We're going to make a piss-poor IMAP client.

HOST = 'peirce.dave.cridland.net'
SERVICE = 'imap'
# Set this to None, typically, for auto-select, or a SASL mechanism name, like:
# MECHANISM = 'DIGEST-MD5'
MECHANISM = None

# Setup sasl object *now*...

# This gets called with questions.
# Obviously, this is crap l11n, and needs fixing.
def secquery(mech, question):
    print "Answering yes to", question
    return True

def callback(mech, vals):
    print "Need user information for",mech.mechname,"login to",mech.sasl.service,"on",mech.sasl.host
    import getpass
    for x,v in vals.items():
        if x == 'password':
            vals[x] = getpass.getpass( 'Password: ' )
        else:
            vals[x] = raw_input( x+': ' )
    print "Fulfilling:",`vals`
    mech.fulfill(vals)
    return

# We'll authenticate as "test". The password is (or was, when I wrote this) "test".
sasl = sasl.sasl(HOST, SERVICE, username='test', secquery=secquery, callback=callback, mech=MECHANISM)

fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

fd.connect((HOST, 143))

f = fd.makefile()

# Read through the banner.
# A real IMAP client would look for capabilities here.
print `f.readline()`

# ... But we'll ask for them explicitly.
f.write('. CAPABILITY\r\n')
f.flush()

caps = f.readline() # Very trusting.
caps = caps.strip()

# Close to vomiting, now:
caps = [ mech.split('=')[1] for mech in caps.split(' ') if mech.startswith('AUTH=') ]

print `f.readline()`

print "Available mechs:", `caps`

mech = sasl.mechlist(caps)

print "Going to use",`mech`,"-",mech.name()

# If we do initial response, here, we could process an empty string to get it.
# This *is* the case on IMAP with SASL-IR.
f.write('. AUTHENTICATE %s\r\n' % mech.name())
f.flush()

# Loop until we're done.
# IMAP SASL profile does base64 everywhere, like many protocols.
# It's up to us to handle that, Suelta expects the real data.

while True:
    stuff = f.readline()
    
    print `stuff`
    
    if stuff[0] == '.':
        break

    if stuff[0] == '+':
        gunk = stuff[2:].decode('base64')
        print "Got:",`gunk`
        my_gunk = mech.process(gunk)
        print "Sending:",`my_gunk`
        if my_gunk is None:
            my_stuff = '+'
        else: 
            my_stuff = ''.join(my_gunk.encode('base64').split('\n'))
        # Note the slightly hairy way you need to encode to avoid linebreaks.
        f.write('%s\r\n' % (my_stuff))
        f.flush()

ok = stuff.split(' ')[1]

if ok == 'OK':
    print "Server says OK."
    if mech.okay():
        print "Mechanism says OK."
        ## Be happy.
    else:
        print "Mutual auth failed: Disaster!"
else:
    print "Auth failed - wrong password?"
