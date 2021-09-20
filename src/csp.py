"""
Implements the Contiguous Sequential Pattern (CSP) algorithm,
only up to the 2nd level CSP, i.e., for reverse engineering "field format" and "message format".
"""

# Development workaround due to laziness
import sys, os
sys.path.insert(0, os.path.abspath("lib"))

from argparse import ArgumentParser
from time import time

# noinspection PyUnresolvedReferences
from tabulate import tabulate
# noinspection PyUnresolvedReferences
from pprint import pprint
# noinspection PyUnresolvedReferences
import IPython

from nemere.utils.loader import SpecimenLoader
from nemere.utils.evaluationHelpers import StartupFilecheck
from nemere.utils.reportWriter import writeReport
from nemere.validation.dissectorMatcher import MessageComparator, DissectorMatcher

from csp.inference import *


if __name__ == '__main__':
    parser = ArgumentParser(
        description='Re-Implementation of the Contiguous Sequential Pattern algorithm.')
    parser.add_argument('pcapfilename', help='Filename of the PCAP to load.')
    parser.add_argument('-i', '--interactive', help='open ipython prompt after finishing the analysis.',
                        action="store_true")
    parser.add_argument('-l', '--layer', type=int, default=2,
                        help='Protocol layer relative to IP to consider. Default is 2 layers above IP '
                             '(typically the payload of a transport protocol).')
    parser.add_argument('-r', '--relativeToIP', default=True, action='store_false')
    args = parser.parse_args()

    filechecker = StartupFilecheck(args.pcapfilename)

    specimens = SpecimenLoader(args.pcapfilename, layer = args.layer, relativeToIP = args.relativeToIP)
    # noinspection PyTypeChecker
    messages = list(specimens.messagePool.keys())  # type: List[L4NetworkMessage]

    coSePa = CSP(messages)
    # first CSP: static fields - SF(v)
    cspLevel1 = coSePa.byBIDEracker()

    print(tabulate([(k.hex(), v[0]) for k, v in cspLevel1.items() if v[0] > len(messages) * 0.3]))

    # recurse CSP




    # interactive
    if args.interactive:
        IPython.embed()

