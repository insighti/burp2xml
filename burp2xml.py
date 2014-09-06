#!/usr/bin/env python
#Developed by Paul Haas, <phaas AT redspin DOT com> under Redspin. Inc.
#Licensed under the GNU Public License version 3.0 (2008-2009)
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
    except ValueError, e: # Bad date, just return the milliseconds
        date = str(milliseconds)
    return date    

def burp_binary_field(field,i,non_printable):
    '''Strip Burp Suite's binary format characters types from our data.    
    The first character after the leading tag describes the type of the data.
        If non_printable is true, keep nonprintable characters
        '''
    if len(field) <= i:
        return None,-1
    elif field[i] == '\x00': # 4 byte integer value
        return str(struct.unpack('>I',field[i+1:i+5])[0]),5        
    elif field[i] == '\x01': # Two possible unsigned long long types
        if field[i+1] == '\x00': # (64bit) 8 Byte Java Date
            ms = struct.unpack('>Q',field[i+1:i+9])[0]        
            date = milliseconds_to_date(ms)
            if type(date) == str:
                value = date
            else:
                value =    date.ctime() # Use the ctime string format for date
        else: # Serial Number only used ocasionally in Burp
            value = str(struct.unpack('>Q',field[i+1:i+9])[0])
        return value,9
    elif field[i] == '\x02': # Boolean Object True/False
        return str(struct.unpack('?',field[i+1:i+2])[0]),2        
    elif field[i] == '\x03' or field[i] == '\x04': # 4 byte length + string        
        length = struct.unpack('>I',field[i+1:i+5])[0]
        #print "Saw string of length",length,"at",i+5,i+5+length
        value = field[i+5:i+5+length]                
        if not non_printable:
                        value = ''.join(c for c in value if c in nvprint) # Remove nonprintables
        if '<' in value or '>' in value or '&' in value: # Sanatize HTML w/CDATA
            value = '<![CDATA[' + value.replace(']]>',']]><![CDATA[') + ']]>' 
        return value,5+length # ** TODO: Verify length by matching end tag **
    print "Unknown binary format",repr(field[i])
    return None,-1

def burp_to_xml(filename,non_printable):
    '''Unzip Burp's file, remove non-printable characters, CDATA any HTML,
    include a valid XML header and trailer, and return a valid XML string.
        if non_printable is true, retain nonprintable characters
        '''

    xml = '' # Our output string
    z = zipfile.ZipFile(filename) # Open Burp's zip file
    burp = z.read('burp','rb') # Read-in the main burp file        
    m = TAG.match(burp,0) # Match a tag at the start of the string
    while m:        
        xml += m.group()            
        index = m.end()    
        etag = m.group().replace('<','</') # Matching tag
        
        m = TAG.match(burp,index) # Attempt to get the next tag
        if not m: # Data folows
            # Read the type of data using Burp's binary data headers        
            value, length = burp_binary_field(burp, index, non_printable)
            if value is None: break
            
            xml += value
            xml += etag
            index += length + len(etag) # Point our index to the next tag
            m = TAG.match(burp,index) # And retrieve it
    
    xml = '<?xml version="1.0"?><burp>' + xml + '</burp>' # XMLify our string
    return xml # And return it

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
            parser.error('Input file is a mandatory parameter!')
            print __doc__
            print parser.print_help()
            exit(1)

    out.write(burp_to_xml(args.file, args.non_printable))
    out.close()
    if args.verbose:
                sys.stderr.write("# Output written to %s\n" % outfile)

if __name__ == '__main__':
    main()

