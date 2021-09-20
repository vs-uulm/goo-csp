

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

    def __init__(self, messages: Iterable[AbstractMessage]):
        self.messages = messages

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    def byGoo(self):
        """original CSP algorithm for reference (see paper, Algorithm 1)"""
        L =  defaultdict(lambda: defaultdict(list))  # type: Dict[int,Dict[bytes, List[Tuple[HashableByteSequence,int]]]]
        sequences = [HashableByteSequence(msg.data, hash(msg)) for msg in self.messages]
        # extract all single bytes as starting set
        for sequence in sequences:
            for offset, intValue in enumerate(sequence.sequence):
                byteValue = bytes([intValue])
                L[1][byteValue].append((sequence,offset))
        k = 2
        while L[k-1]:
            for candidate in L[k-1].items():
                support = CSP.calcSupport(candidate)
                if support < CSP.MIN_SUPPORT:
                    del L[k-1][candidate[0]]
                L[k] = CSP.extractCandidates(L[k-1])
            k += 1
        SubSeqSet = chain.from_iterable(L.values())  # type: Iterable
        SubSeqSet = CSP.deleteSubSet(SubSeqSet)  # type: Sequence
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

    def byBIDEracker(self):
        """
        More efficient BIDE-based alternative to the original CSP (see #byGoo()).

        We do not count subsequences per flow (see Equations 3-5 in paper;
        would not work for DHCP, DNS, ...) but for the whole trace.
        """
        MessageBIDE.MIN_SUPPORT = CSP.MIN_SUPPORT
        bide = MessageBIDE(self.messages)
        return bide.mostFrequent()

    def recursiveCSPbyBIDEracker(self):
        """(see paper, Algorithm 3)"""
        pass


    