#!/usr/bin/env python3
import argparse
import gzip
import ipaddress
import os
import sys
import urllib.request

if sys.version_info[0] != 3 or sys.version_info[1] < 3:
    print("This script requires Python version 3.3 or above")
    sys.exit(1)

parser = argparse.ArgumentParser(
    description='''download block lists from iblocklist.com
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
    '-i',
    '--infile',
    default='lists.input',
    help='input file with urls of lists'
)
parser.add_argument(
    '-o',
    '--outfile',
    default='ipfilter.dat',
    help='output file'
)
args = parser.parse_args()

def dprint(level, *a, **kwargs):
    if args.debug >= level:
        print(*a, file=sys.stderr, **kwargs)

print(os.path.dirname(os.path.realpath(__file__)))
if os.path.isabs(args.infile):
	input = args.infile
else:
	input = os.path.join(os.getcwd(), args.infile)
	if not os.access(input, os.R_OK):
		input = os.path.join(os.path.dirname(os.path.realpath(__file__)),
			args.infile)

if not os.access(input, os.R_OK):
	dprint(0,'cannot read input file:', args.infile)

nets = []
for line in open(input, 'r'):
    url = line.split('#')[0].strip()
    if not url:
        continue
    try:
        response = urllib.request.urlopen(url)
    except Exception as e:
        dprint(0,'%s: ' % url, e)
    else:
        dprint(1,url)
        for line in gzip.open(response):
            line = line.decode(errors='ignore').strip()
            a = line.rsplit(':',1)
            if len(a) != 2:
                dprint(2,'skipped line:', line)
                continue
            comment, range = a
            a = range.split('-')
            if len(a) != 2:
                dprint(2,'bad ip range:', line)
                continue
            start,end = map(ipaddress.IPv4Address, a)
            nets.extend(list(ipaddress.summarize_address_range(start, end)))

outf = open(args.outfile,'w')
for n in sorted(list(set(nets))):
    print(n, file=outf)

outf.close()
