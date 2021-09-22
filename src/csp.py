"""
Implements the Contiguous Sequential Pattern (CSP) algorithm,
only up to the 2nd level CSP, i.e., for reverse engineering "field format" and "message format".
"""

# Development workaround due to laziness
import logging
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
from nemere.inference.segmentHandler import symbolsFromSegments
from nemere.validation.dissectorMatcher import MessageComparator, DissectorMatcher
from nemere.validation.netzobFormatMatchScore import MessageScoreStatistics
from nemere.visualization.simplePrint import SegmentPrinter

from csp.inference import *

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
# logger.setLevel(logging.DEBUG)
# logger.debug("log level DEBUG")

if __name__ == '__main__':
    parser = ArgumentParser(
        description='Re-Implementation of the Contiguous Sequential Pattern algorithm.')
    parser.add_argument('pcapfilename', help='Filename of the PCAP to load.')
    parser.add_argument('-i', '--interactive', help='open ipython prompt after finishing the analysis.',
                        action="store_true")
    parser.add_argument('-l', '--layer', type=int, default=2,
                        help='Protocol layer relative to IP to consider. Default is 2 layers above IP '
                             '(typically the payload of a transport protocol).')
    parser.add_argument('-r', '--relativeToIP', action='store_false')
    parser.add_argument('-s', '--iterate-min-support', action='store_true')
    args = parser.parse_args()
    layer = args.layer
    relativeToIP = args.relativeToIP

    filechecker = StartupFilecheck(args.pcapfilename)

    specimens = SpecimenLoader(args.pcapfilename, layer = layer, relativeToIP = relativeToIP)
    # noinspection PyTypeChecker
    messages = list(specimens.messagePool.keys())  # type: List[L4NetworkMessage]

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # TODO iterate values for min_support: 30..80 ?! and calculate the FMS for each to find an optimum.
    if args.iterate_min_support:
        minSupportList = (a/10 for a in range(3,9))
    else:
        minSupportList = [.6]
    for minSupport in minSupportList:
        CSP.MIN_SUPPORT = minSupport
        inferenceStart = time()

        coSePa = CSP(messages)
        # print(tabulate([(k.hex(), v[0]) for k, v in cspLevel1.items() if v[0] > len(messages) * 0.3]))

        fieldDefinitions = coSePa.recursiveCSPbyBIDEracker()
        segmentedMessages = coSePa.fieldDefinitions2segments(fieldDefinitions)

        inferenceDuration = time() - inferenceStart
        print("Contiguous Sequential Pattern inference complete.")
        # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

        comparator = MessageComparator(specimens, layer=layer, relativeToIP=relativeToIP)
        print("Dissection complete.")
        symbols = symbolsFromSegments(segmentedMessages)
        comparator.pprintInterleaved(symbols)
        # segPrt = SegmentPrinter(segmentedMessages)
        # segPrt.toConsole()
        # calc FMS per message
        print("Calculate FMS...")
        message2quality = DissectorMatcher.symbolListFMS(comparator, symbols)
        MessageScoreStatistics.printMinMax({(CSP.MIN_SUPPORT, msg) : fms for msg, fms in message2quality.items()})
        # write statistics to csv
        writeReport(message2quality, inferenceDuration, comparator,
                    f"csp-messageformat_{CSP.MIN_SUPPORT}", filechecker.reportFullPath)


    # TODO perform FTR


    # interactive
    if args.interactive:
        IPython.embed()

