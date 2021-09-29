"""
Netzob as segmenter for field classification and recognition.
"""

# Development workaround due to laziness
import sys, os
sys.path.insert(0, os.path.abspath("lib"))

import logging
from typing import List, Dict, Tuple
from argparse import ArgumentParser
from time import time
from itertools import chain
import matplotlib.pyplot as plt

# noinspection PyUnresolvedReferences
from tabulate import tabulate
# noinspection PyUnresolvedReferences
from pprint import pprint
# noinspection PyUnresolvedReferences
import IPython

from netzob import all as netzob
from netzob.Model.Vocabulary.Messages.AbstractMessage import AbstractMessage
from netzob.Model.Vocabulary.Messages.L4NetworkMessage import L4NetworkMessage

# logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()
# logger.setLevel(logging.DEBUG)
# logger.debug("log level DEBUG")

from nemere.utils.loader import SpecimenLoader
from nemere.utils.evaluationHelpers import StartupFilecheck, TitleBuilder
from nemere.utils.reportWriter import writeReport, SegmentClusterGroundtruthReport, CombinatorialClustersReport, \
    IndividualClusterReport, writeFieldTypesTikz, writeSemanticTypeHypotheses, getMinMeanMaxFMS
from nemere.inference.segmentHandler import segmentsFromSymbols
from nemere.inference.templates import DBSCANadjepsClusterer, MemmapDC, DelegatingDC
from nemere.validation.clusterInspector import SegmentClusterCauldron
from nemere.validation.dissectorMatcher import MessageComparator, DissectorMatcher
import nemere.validation.netzobFormatMatchScore as fms
from nemere.visualization.distancesPlotter import SegmentTopology

debug = True
"""Some modules and methods contain debug output that can be activated by this flag."""

# default similarity threshold
thresh = 70

# optimal similarity threshold for some evaluation traces (from -100s):
optThresh = {
    "dhcp_SMIA2011101X-filtered_maxdiff-"   : 76,
    "dns_ictf2010_maxdiff-"                 : 51,
    "dns_ictf2010-new_maxdiff-"             : 50,
    "nbns_SMIA20111010-one_maxdiff-"        : 53,
    "ntp_SMIA-20111010_maxdiff-"            : 66,
    "smb_SMIA20111010-one-rigid1_maxdiff-"  : 53,
	"awdl-filtered"                         : 57,
    "au-wifi-filtered"                      : 51,
}

analysisTitle = "netzob-segments"


def getNetzobInference(l5msgs: List[AbstractMessage], minEquivalence=70):
    """
    Imports the application layer messages from a PCAP and applies Format.clusterByAlignment() to them.

    :param l5msgs: A list of messages to infer
    :param minEquivalence: the similarity threshold for the clustering
    :type minEquivalence: int
    :return: list of symbols inferred by clusterByAlignment from pcap trace
    """
    import time #, gc

    print(f"Start netzob inference with minEquivalence {minEquivalence}...")
    starttime = time.time()
    symbollist = netzob.Format.clusterByAlignment(l5msgs, minEquivalence=minEquivalence, internalSlick=True)
    runtime = time.time() - starttime
    print('Inferred in {:.3f}s'.format(runtime))
    return symbollist, runtime


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
    parser.add_argument('-s', '--similarity-threshold', type=int, help='Similarity threshold to use.')
    parser.add_argument('-p', '--with-plots',
                        help='Generate plots of true field types and their distances.',
                        action="store_true")
    args = parser.parse_args()

    layer = args.layer
    relativeToIP = args.relativeToIP
    withplots = args.with_plots
    filechecker = StartupFilecheck(args.pcapfilename)

    specimens = SpecimenLoader(args.pcapfilename, layer = layer, relativeToIP = relativeToIP)
    # noinspection PyTypeChecker
    messages = list(specimens.messagePool.keys())  # type: List[L4NetworkMessage]

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    comparator = MessageComparator(specimens, layer=layer, relativeToIP=relativeToIP)
    print("Dissection complete.")
    print(f'\nNetzob Inference of {specimens.pcapFileName}...')
    # dict ( similaritythreshold : dict ( symbol : (quality, fieldcount, exactf, nearf, uospecific) ) )
    mThresh = thresh
    if args.similarity_threshold:
        mThresh = args.similarity_threshold
    else:
        # use optimum for trace if a value is known
        for pcap, simthr in optThresh.items():
            if pcap in specimens.pcapFileName:
                mThresh = simthr
                break
    symbols, runtime = getNetzobInference(messages, mThresh)

    print('\nCalculate Format Match Score...')
    swstart = time()
    # (thresh, msg) : fms
    message2quality = DissectorMatcher.symbolListFMS(comparator, symbols)
    formatmatchmetrics = {(mThresh, msg): fms for msg, fms in message2quality.items()}
    print('Calculated in {:.3f}s'.format(time() - swstart))
    mmm = getMinMeanMaxFMS([round(q.score, 3) for q in formatmatchmetrics.values()])
    print('Prepared in {:.3f}s'.format(time() - swstart))
    print('Writing report...')
    swstart = time()
    reportFolder = fms.writeReport(formatmatchmetrics, plt, {mThresh: runtime}, specimens, comparator)
    print('Written in {:.3f}s'.format(time() - swstart))
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    segmentedMessages = segmentsFromSymbols(symbols)

    # perform FTR
    chainedSegments = list(chain.from_iterable(segmentedMessages))
    if len(chainedSegments) ** 2 > MemmapDC.maxMemMatrix:
        dc = MemmapDC(chainedSegments)
    else:
        dc = DelegatingDC(chainedSegments)
    clusterer = DBSCANadjepsClusterer(dc, chainedSegments, S=24.0)
    cauldron = SegmentClusterCauldron(clusterer, analysisTitle)
    cauldron.clustersOfUniqueSegments()
    fTypeTemplates = cauldron.exportAsTemplates()
    inferenceParams = TitleBuilder(analysisTitle, None, None, clusterer)

    ftclusters = {ftc.fieldtype: ftc.baseSegments for ftc in fTypeTemplates}
    """ftclusters is a mixed list of MessageSegment and Template"""
    ftclusters["Noise"] = cauldron.noise

    # # # # # # # # # # # # # # # # # # # # # # # #
    # Report: write cluster elements to csv
    elementsReport = SegmentClusterGroundtruthReport(comparator, dc.segments, filechecker)
    elementsReport.write(ftclusters)
    # # # # # # # # # # # # # # # # # # # # # # # #

    # # # # # # # # # # # # # # # # # # # # # # # #
    # # Report: allover clustering quality statistics
    report = CombinatorialClustersReport(elementsReport.groundtruth, filechecker)
    report.write(ftclusters, inferenceParams.plotTitle)

    # field-type-wise cluster quality statistics
    report = IndividualClusterReport(elementsReport.groundtruth, filechecker)
    # add column $d_max$ to report
    cluDists = {lab: clusterer.distanceCalculator.distancesSubset(clu) for lab, clu in ftclusters.items()}
    cluDistsMax = {lab: clu.max() for lab, clu in cluDists.items()}
    report.addColumn(cluDistsMax, "$d_max$")
    report.write(ftclusters, inferenceParams.plotTitle)
    clusterStats = report.precisionRecallList
    # # # # # # # # # # # # # # # # # # # # # # # #

    if withplots:
        # distance Topology plot
        topoplot = SegmentTopology(clusterStats, fTypeTemplates, cauldron.noise, dc)
        topoplot.writeFigure(specimens, inferenceParams, elementsReport, filechecker)
    writeFieldTypesTikz(comparator, segmentedMessages, fTypeTemplates, filechecker)
    filechecker.writeReportMetadata(None)
    # # # # # # # # # # # # # # # # # # # # # # # #
    writeSemanticTypeHypotheses(cauldron, filechecker)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # interactive
    if args.interactive:
        IPython.embed()

