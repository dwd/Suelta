import socket
import base64

import suelta

# Make working with both Python 2.6+ and 3 easier
from suelta.util import bytes

# Walkthrough - and test - for Suelta.
# We're going to make a piss-poor IMAP client.

HOST = 'peirce.dave.cridland.net'
SERVICE = 'imap'
# Set this to None, typically, for auto-select, or a SASL mechanism name, like:
# MECHANISM = 'DIGEST-MD5'
MECHANISM = None

# Setup sasl object *now*...

# This gets called with questions.
def secquery(mech, question):
    print("Answering yes to: %s" % question)
    return True

def callback(mech, vals):
    print("Need user information for %s login to %s on %s" % (mech.name, mech.sasl.service, mech.sasl.host))
    import getpass
    for x, v in list(vals.items()):
        if x == 'password':
            vals[x] = getpass.getpass( 'Password: ' )
        else:
            vals[x] = input( x+': ' )

    print("Fulfilling: %s" % vals)
    mech.fulfill(vals)

# We'll authenticate as "test". The password is (or was, when I wrote this) "test".
sasl = suelta.SASL(HOST, SERVICE,
                   username='test',
                   sec_query=secquery,
                   request_values=callback,
                   mech=MECHANISM)

fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

fd.connect((HOST, 143))

f = fd.makefile(mode='rw')

# Read through the banner.
# A real IMAP client would look for capabilities here.
print(f.readline())

# ... But we'll ask for them explicitly.
f.write('. CAPABILITY\r\n')
f.flush()

caps = f.readline() # Very trusting.
caps = caps.strip()

# Close to vomiting, now:
caps = [ mech.split('=')[1] for mech in caps.split(' ') if mech.startswith('AUTH=') ]

print(f.readline())

print("Available mechs: %s" % caps)

mech = sasl.choose_mechanism(caps)

print("Going to use %s - %s" % (mech, mech.name))

# If we do initial response, here, we could process an empty string to get it.
# This *is* the case on IMAP with SASL-IR.
f.write('. AUTHENTICATE %s\r\n' % mech.name)
f.flush()

# Loop until we're done.
# IMAP SASL profile does base64 everywhere, like many protocols.
# It's up to us to handle that, Suelta expects the real data.

while True:
    stuff = f.readline()

    print(stuff)

    if stuff[0] == '.':
        break

    if stuff[0] == '+':
        gunk = base64.b64decode(bytes(stuff[2:]))
        print("Got: %s" % gunk)
        my_gunk = mech.process(gunk)
        print("Sending: %s" % my_gunk)

        if my_gunk is None:
            my_stuff = b'+'
        else:
            my_stuff =base64.b64encode(my_gunk).replace(b'\n', b'')

        my_stuff += b'\r\n'
        my_stuff = my_stuff.decode('utf-8')

        # Note the slightly hairy way you need to encode to avoid linebreaks.
        f.write(my_stuff)
        f.flush()

ok = stuff.split(' ')[1]

if ok == 'OK':
    print("Server says OK.")
    if mech.okay():
        print("Mechanism says OK.")
        ## Be happy.
    else:
        print("Mutual auth failed: Disaster!")
else:
    print("Auth failed - wrong password?")
