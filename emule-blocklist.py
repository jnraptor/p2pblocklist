#!/usr/bin/env python3
import argparse
import gzip
import ipaddress
import os
import sys
import urllib.request
from zipfile import ZipFile
import io

url = "http://upd.emule-security.org/ipfilter.zip"
extract = "guarding.p2p"

if sys.version_info[0] != 3 or sys.version_info[1] < 3:
    print("This script requires Python version 3.3 or above")
    sys.exit(1)

parser = argparse.ArgumentParser(
    description='''download block lists from emule-security
    and convert to ipfilter.dat.
    ''',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter
)
parser.add_argument(
    '-D',
    '--debug',
    type=int,
    default=0,
    choices=range(0, 3),
    help='debug flag'
)
parser.add_argument(
    '-o',
    '--outfile',
    default='emule-ipfilter.dat',
    help='output file'
)
args = parser.parse_args()

def dprint(level, *a, **kwargs):
    if args.debug >= level:
        print(*a, file=sys.stderr, **kwargs)

print(os.path.dirname(os.path.realpath(__file__)))

try:
    response = urllib.request.urlopen(url)
except Exception as e:
    dprint(0,'%s: ' % url, e)
else:
    dprint(1,url)
    zf = ZipFile(io.BytesIO(response.read()))
    zf.extractall(os.getcwd())
    zf.close()

    extracted = os.path.join(os.getcwd(), extract)
    if not os.access(extracted, os.R_OK):
	    dprint(0,'cannot read extracted file: ', extract)
    else:
        nets = []

        with open(extracted, 'r') as fp:
            for cnt, line in enumerate(fp):
                line = line.strip()
                a = line.rsplit(' , ')
                if len(a) != 3:
                    dprint(2,'skipped line:', line)
                    continue
                range, extra, comment = a
                a = range.split(' - ')
                if len(a) != 2:
                    dprint(2,'bad ip range:', line)
                    continue
                start,end = map(ipaddress.IPv4Address, a)
                nets.extend(list(ipaddress.summarize_address_range(start, end)))
        
        outf = open(args.outfile,'w')
        for n in set(nets):
            print(n, file=outf)
        outf.close()
