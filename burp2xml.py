#!/usr/bin/env python
# Developed by Paul Haas, <phaas AT redspin DOT com> under Redspin. Inc.
# Licensed under the GNU Public License version 3.0 (2008-2009)
# Forked and further improved by Lukas Kuzmiak, <lukas.kuzmiak AT insighti DOT org> under insighti a.s.

'''Process Burp Suite Professional's output into a well-formed XML document.

Burp Suite Pro's session file zipped into a combination of XML-like tags 
containing leading binary headers with type and length definitions followed by
the actual data.  The theory is that this allows the file to read sequentially
rather than requiring tedious XML parsing.  However, without re-writing Burp's
internal parser, we have no way to extract results from its files without
loading the results in Burp.  

This tool takes a zipped Burp file and outputs a XML document based upon the
provided arguments which allows regular XPATH queries and XSL transformations.
'''

import datetime, string, re, struct, zipfile, sys

CHUNK_SIZE = 10240 # use negative number to read the whole file at once

TAG = re.compile('</?(\w*)>',re.M) # Match a XML tag
nvprint = string.printable.replace('\x0b','').replace('\x0c','') # Printables

def milliseconds_to_date(milliseconds):
    '''Convert milliseconds since Epoch (from Java) to Python date structure:
    See: http://java.sun.com/j2se/1.4.2/docs/api/java/util/Date.html
    
    There is no direct way to convert milliseconds since Epoch to Python object
    So we convert the milliseconds to seconds first as a POSIX timestamp which
    can be used to get a valid date, and then use the parsed values from that
    object along with converting mili -> micro seconds in a new date object.'''

    try:
        d = datetime.datetime.fromtimestamp(milliseconds/1000)
        date = datetime.datetime(d.year,d.month,d.day,d.hour,d.minute,d.second,
            (milliseconds%1000)*1000)        
    except ValueError: # Bad date, just return the milliseconds
        date = str(milliseconds)
    return date    

def parse_field(data, offset, field_type, field_len, non_printable):
    if (len(data) - offset) < field_len:
        sys.stderr.write("Something went terribly wrong, not enough data for field parsing. Was parsing type %d of length %d but only got %d data\n"
                             % (field_type, field_len, len(data) - offset))
        return None

    if field_type == 0: # INTEGER
        return str(struct.unpack('>I', data[offset:offset+field_len])[0])

    elif field_type == 1: # LONG
        unpacked = struct.unpack('>Q', data[offset:offset+field_len])[0]
        if data[offset] == '\x00': # (64bit) 8 Byte Java Date
            date = milliseconds_to_date(unpacked)
            return date if type(date) == str else date.ctime()
        else: # Serial Number only used ocasionally in Burp
            return str(unpacked)
    
    elif field_type == 2: # BOOLEAN
        return str(struct.unpack('?', data[offset:offset+field_len])[0])
    
    elif field_type == 3: # STRING
        value = data[offset:offset+field_len]
        if not non_printable:
            value = ''.join(c for c in value if c in nvprint) # Remove nonprintables
        if '<' in value or '>' in value or '&' in value: # Sanatize HTML w/CDATA
            value = '<![CDATA[' + value.replace(']]>',']]><![CDATA[') + ']]>'
        return value

def identify_field(data, offset):
    if (len(data) - offset) < 1:
        sys.stderr.write("Not enough data, but haven't reached end of stream yet - corrupted data?\n")
        return None, -1, 0
    if data[offset] == '\x00': # 4 byte integer value
        return 0, 4, 1
    elif data[offset] == '\x01': # unsigned long long type
        return 1, 8, 1
    elif data[offset] == '\x02': # Boolean Object True/False
        return 2, 1, 1
    elif data[offset] == '\x03' or data[offset] == '\x04': # 4 byte length + string
        if (len(data) - offset) < 5:
            return None, -1, 0
        length = struct.unpack('>I', data[offset+1:offset+5])[0]
        return 3, length, 5
    else:
        sys.stderr.write("Unknown datatype, burp upgraded session files structure?\n")
        return None, -1, 0

def burp_to_xml(filename, output, non_printable):
    '''Unzip Burp's file, remove non-printable characters, CDATA any HTML,
    include a valid XML header and trailer, and return a valid XML string.
    if non_printable is true, retain nonprintable characters'''
    
    with zipfile.ZipFile(filename) as z:
        with z.open('burp', 'r') as f:
            output.write('<?xml version="1.0"?><burp>')
            chunk = f.read(100) # read just the beginning
            m = TAG.match(chunk, 0)
            while m:
                output.write(m.group())
                offset = m.end()
                etag = m.group().replace('<','</')
                m = TAG.match(chunk, offset)
                if not m:
                    if len(chunk) - offset == 0:
                        break # end of file
                    field_type, field_len, used_bytes = identify_field(chunk, offset)
                    offset += used_bytes
                    if field_type is None:
                        break # corruption - bad data?

                    remaining = (len(chunk) - offset) - field_len - len(etag);
                    if remaining < 0:
                        chunk += f.read(-remaining) # read what we're missing
                        remaining = 0

                    output.write(parse_field(chunk, offset, field_type, field_len, non_printable))
                    output.write(etag)
                    offset += field_len + len(etag)

                    if remaining == 0:
                        chunk = f.read(CHUNK_SIZE) # force python to free data by re-using the same buffer
                        offset = 0
                    elif remaining < 100:
                        chunk += f.read(CHUNK_SIZE)

                    m = TAG.match(chunk, offset)
                    
            output.write('</burp>')

def main():
    '''Called if script is run from the command line.'''

    from argparse import ArgumentParser
    import sys

    parser = ArgumentParser(description=__doc__)
    parser.add_argument("-f", "--file", help="Input file (burp session file)")
    parser.add_argument("-o", "--output", help="Output file (clean XML file)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Be more verbose")
    parser.add_argument("-n", "--non-printable", action="store_true", help="Retain non-printable characters")
    
    args = parser.parse_args()

    if args.file:
            if args.output == "-":
                out = sys.stdout
            else:
                out = open(args.output, 'wb') if args.output else open(args.file + '.xml', 'wb')
    else:
        print __doc__
        parser.error('Input file is a mandatory parameter!')

    burp_to_xml(args.file, out, args.non_printable)
    out.close()
    
    if args.verbose:
                sys.stderr.write("# Output written to %s\n" % outfile)

if __name__ == '__main__':
    main()

