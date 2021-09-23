"""
Implements the Contiguous Sequential Pattern (CSP) algorithm,
only up to the 2nd level CSP, i.e., for reverse engineering "field format" and "message format".
"""

# Development workaround due to laziness
import sys, os
sys.path.insert(0, os.path.abspath("lib"))

import logging
from typing import List
from argparse import ArgumentParser
from time import time
from itertools import chain

# noinspection PyUnresolvedReferences
from tabulate import tabulate
# noinspection PyUnresolvedReferences
from pprint import pprint
# noinspection PyUnresolvedReferences
import IPython

from netzob.Model.Vocabulary.Messages.L4NetworkMessage import L4NetworkMessage

# logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()
# logger.setLevel(logging.DEBUG)
# logger.debug("log level DEBUG")

from nemere.utils.loader import SpecimenLoader
from nemere.utils.evaluationHelpers import StartupFilecheck, TitleBuilder
from nemere.utils.reportWriter import writeReport, SegmentClusterGroundtruthReport, CombinatorialClustersReport, \
    IndividualClusterReport, writeFieldTypesTikz, writeSemanticTypeHypotheses
from nemere.inference.segmentHandler import symbolsFromSegments
from nemere.inference.templates import DBSCANadjepsClusterer, MemmapDC, DelegatingDC
from nemere.validation.clusterInspector import SegmentClusterCauldron
from nemere.validation.dissectorMatcher import MessageComparator, DissectorMatcher
from nemere.validation.netzobFormatMatchScore import MessageScoreStatistics
from nemere.visualization.distancesPlotter import SegmentTopology

from csp.inference import CSP

analysisTitle = "csp-messageformat"

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
    parser.add_argument('-f', '--field-type-recognition', action='store_true')
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
    # TODO iterate values for min_support and calculate the FMS for each to find an optimum.
    if args.iterate_min_support:
        minSupportList = (a/10 for a in range(3,10))
    else:
        minSupportList = [.6]
    formatmatchmetrics = dict()
    segmentedMessages = []  # prevent PyCharm warning
    comparator = MessageComparator(specimens, layer=layer, relativeToIP=relativeToIP)
    print("Dissection complete.")
    for minSupport in minSupportList:
        CSP.MIN_SUPPORT = minSupport
        print(f"Perform CSP with min support {CSP.MIN_SUPPORT}")
        inferenceStart = time()

        coSePa = CSP(messages)
        # print(tabulate([(k.hex(), v[0]) for k, v in cspLevel1.items() if v[0] > len(messages) * 0.3]))
        fieldDefinitions = coSePa.recursiveCSPbyBIDEracker()
        segmentedMessages = coSePa.fieldDefinitions2segments(fieldDefinitions)

        inferenceDuration = time() - inferenceStart
        print("Contiguous Sequential Pattern inference complete.")

        # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
        symbols = symbolsFromSegments(segmentedMessages)
        # comparator.pprintInterleaved(symbols)
        # calc FMS per message
        print("Calculate FMS...")
        message2quality = DissectorMatcher.symbolListFMS(comparator, symbols)
        formatmatchmetrics.update({(CSP.MIN_SUPPORT, msg): fms for msg, fms in message2quality.items()})
        # write statistics to csv
        writeReport(message2quality, inferenceDuration, comparator,
                    f"{analysisTitle}_{CSP.MIN_SUPPORT}", filechecker.reportFullPath, True)
    MessageScoreStatistics.printMinMax(formatmatchmetrics)
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    if args.field_type_recognition:
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

