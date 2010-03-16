# Copyright 2007-2010 David Alan Cridland
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import stringprep
import unicodedata

def saslprep( foo, errors='strict' ):
    if isinstance( foo, str ):
        foo = foo.decode( 'us-ascii' )
    ofoo = u''
    for x in foo:
        if stringprep.in_table_c12( x ):
            ofoo += ' '
        elif not stringprep.in_table_b1( x ):
            ofoo += x
    foo = unicodedata.normalize( 'NFKC', ofoo )
    ofoo = u''
    first_is_randal = False
    if len(foo):
        first_is_randal = stringprep.in_table_d1( foo[0] )
        if first_is_randal:
            if not stringprep.in_table_d1( foo[-1] ):
                raise UnicodeError, "Section 6.3 [end]"
    for x in range(len(foo)):
        if errors=='strict' and stringprep.in_table_a1( foo[x] ):
            raise UnicodeError, "Unassigned Codepoint"
        if stringprep.in_table_c12( foo[x] ):
            raise UnicodeError, "In table C.1.2"
        if stringprep.in_table_c21( foo[x] ):
            raise UnicodeError, "In table C.2.1"
        if stringprep.in_table_c22( foo[x] ):
            raise UnicodeError, "In table C.2.2"
        if stringprep.in_table_c3( foo[x] ):
            raise UnicodeError, "In table C.3"
        if stringprep.in_table_c4( foo[x] ):
            raise UnicodeError, "In table C.4"
        if stringprep.in_table_c5( foo[x] ):
            raise UnicodeError, "In table C.5"
        if stringprep.in_table_c6( foo[x] ):
            raise UnicodeError, "In table C.6"
        if stringprep.in_table_c7( foo[x] ):
            raise UnicodeError, "In table C.7"
        if stringprep.in_table_c8( foo[x] ):
            raise UnicodeError, "In table C.8"
        if stringprep.in_table_c9( foo[x] ):
            raise UnicodeError, "In table C.9"
        if x:
            if first_is_randal and stringprep.in_table_d2( foo[x] ):
                raise UnicodeError, "Section 6.2"
            if not first_is_randal and x!=(len(foo)-1) and stringprep.in_table_d1( foo[x] ):
                raise UnicodeError, "Section 6.3"
        else:
            first = False
    return foo
    
