

from typing import List, Sequence, Tuple, Dict, Iterable, ItemsView, Union
import random, logging
from itertools import groupby, product, chain, combinations
from collections import Counter, defaultdict
from abc import ABC, abstractmethod

import numpy
from scipy.stats import pearsonr
from pyitlib import discrete_random_variable as drv
from netzob.Model.Vocabulary.Messages.AbstractMessage import AbstractMessage
from netzob.Model.Vocabulary.Messages.L2NetworkMessage import L2NetworkMessage
from netzob.Model.Vocabulary.Messages.L4NetworkMessage import L4NetworkMessage

from nemere.inference.analyzers import Value
from nemere.inference.segments import TypedSegment
from nemere.inference.trackingBIDE import BIDEracker, MessageBIDE, HashableByteSequence
from tabulate import tabulate


class CSP(object):
    MIN_SUPPORT = .3

    def __init__(self, messages: Sequence[AbstractMessage]):
        self.messages = messages

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    def byGoo(self):
        """original CSP algorithm for reference (see paper, Algorithm 1)"""
        L =  defaultdict(lambda: defaultdict(list))  # type: Dict[int, Dict[bytes, List[Tuple[HashableByteSequence,int]]]]
        sequences = [HashableByteSequence(msg.data, hash(msg)) for msg in self.messages]
        # extract all single bytes as starting set
        for sequence in sequences:
            for offset, intValue in enumerate(sequence.sequence):
                byteValue = bytes([intValue])
                L[1][byteValue].append((sequence,offset))
        k = 2
        while L[k-1]:
            for candidate in L[k-1].items():
                support = type(self).calcSupport(candidate)
                if support < type(self).MIN_SUPPORT:
                    del L[k-1][candidate[0]]
                L[k] = type(self).extractCandidates(L[k-1])
            k += 1
        SubSeqSet = chain.from_iterable(L.values())  # type: Iterable
        SubSeqSet = type(self).deleteSubSet(SubSeqSet)  # type: Sequence
        return SubSeqSet

    @staticmethod
    def calcSupport(candidate: Tuple[bytes, List]) -> int:
        """:param candidate: may be the ItemsView of a byte value and a list of tuples of (sequence,offset)."""
        raise NotImplementedError()

    @staticmethod
    def extractCandidates(sequences: Dict[bytes, List[Tuple[HashableByteSequence,int]]]) \
            -> Dict[bytes, List[Tuple[HashableByteSequence,int]]]:
        """The paper is very vague about this function. It works "according to the Apriori strategy",
        probably AprioriTID."""
        raise NotImplementedError()

    @staticmethod
    def deleteSubSet(SubSeqSet: Iterable) -> Sequence:
        """Delete all candidates that are subsequences of any other sequence."""
        raise NotImplementedError()
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def byBIDEracker(self) -> Dict[bytes, Tuple[int, Dict[HashableByteSequence, List[int]]]]:
        """
        More efficient BIDE-based alternative to the original CSP (see #byGoo()).

        We do not count subsequences per flow (see Equations 3-5 in paper;
        would not work for DHCP, DNS, ...) but for the whole trace.
        """
        MessageBIDE.MIN_SUPPORT = type(self).MIN_SUPPORT
        # we use self.messages as FlowSequenceSet and as identical MessageSequenceSet
        bide = MessageBIDE(self.messages)
        # BIDE returns all locally frequent values also, which we are not interested in here.
        return {k: v for k, v in bide.mostFrequent().items() if v[0] > len(self.messages) * type(self).MIN_SUPPORT}

    def recursiveCSPbyBIDEracker(self):
        """(see paper, Algorithm 3)"""
        fieldDefinitions = list()  # needs to hold for each field:
                                   #    type, values (multiple ones for non-SF(v)), <-- for additional fields (Algo. 4)
                                   #    occurrences (seq/msg, offset) per value     <-- to generate segments afterwards
        # we use self.messages as MessageSequenceSet in byBIDEracker() and for recursion afterwards
        cspLevel1 = self.byBIDEracker()
        # (byteValue, occurrences) are the FieldF_i from the paper
        for byteValue, occurrences in cspLevel1.items():
            posVar = type(self).posVar(occurrences)

        # self.messages

    @staticmethod
    def posVar(occurrences: Tuple[int, Dict[HashableByteSequence, List[int]]]):
        """Calculate the position variance of all occurrences for the field implicitly described by the occurrences."""
        return numpy.var([o for m, o in CSP.iterateOccurrences(occurrences)])

    @staticmethod
    def support(occurrences: Tuple[int, Dict[HashableByteSequence, List[int]]]):
        """Calculate the support for the field implicitly described by the occurrences."""
        return occurrences[0]

    @staticmethod
    def minOffset(occurrences: Tuple[int, Dict[HashableByteSequence, List[int]]]):
        """Calculate the minimum offset for the field implicitly described by the occurrences."""
        return min(o for m, o in CSP.iterateOccurrences(occurrences))

    @staticmethod
    def maxDepth(occurrences: Tuple[int, Dict[HashableByteSequence, List[int]]], length: int):
        """Calculate the maximum of offset + length for the field implicitly described by the occurrences."""
        return max(o for m, o in CSP.iterateOccurrences(occurrences)) + length

    @staticmethod
    def removeSequences(byteSeq: Iterable[HashableByteSequence],
                       filterList: Iterable[HashableByteSequence]):
        """
        To extract the filterList from occurrences:
        >>> occurrences = (1, {HashableByteSequence(b"a"): [1]})  # type: Tuple[int, Dict[HashableByteSequence, List[int]]]
        >>> occurrences[1].keys()

        :return: A copy of the list of sequences in byteSeq without those contained in the given occurrences.
        """
        return [seq for seq in byteSeq if byteSeq not in filterList]

    @staticmethod
    def truncateSequences(byteSeq: Iterable[HashableByteSequence], minOffset: int, maxDepth: int):
        """:return: A copy of the list of sequences in byteSeq without those contained in the given occurrences."""
        return [
            HashableByteSequence( seq.sequence[minOffset:maxDepth], hash((hash(seq),minOffset,maxDepth)) )
            for seq in byteSeq]

    @staticmethod
    def iterateOccurrences(occurrences: Tuple[int, Dict[HashableByteSequence, List[int]]]):
        for msg, offsets in occurrences[1].items():
            for o in offsets:
                yield msg, o
