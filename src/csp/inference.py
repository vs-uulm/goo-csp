from typing import List, Sequence, Tuple, Dict, Iterable, ItemsView, Union
import logging
from itertools import groupby, product, chain, combinations
from collections import Counter, defaultdict
from dataclasses import dataclass

import numpy
from netzob.Model.Vocabulary.Messages.AbstractMessage import AbstractMessage

from nemere.inference.analyzers import Value
from nemere.inference.segments import MessageSegment, TypedSegment
from nemere.inference.trackingBIDE import BIDEracker, MessageBIDE, HashableByteSequence

@dataclass
class Field:
    ftype: str
    values: Dict[bytes, Tuple[int, Dict[HashableByteSequence, List[int]]]]

    def __init__(self, ftype: str, values: Dict[bytes, Tuple[int, Dict[HashableByteSequence, List[int]]]]):
        super().__init__()
        self.ftype = ftype
        self.values = values

class HashableTruncatedByteSequence(HashableByteSequence):
    def __init__(self, sequence:bytes, ohash:int=None, offset:int=0):
        super().__init__(sequence, ohash)
        self._offset = offset

    @property
    def offset(self):
        return self._offset

class CSP(object):
    MIN_SUPPORT = .6

    def __init__(self, messages: Sequence[AbstractMessage]):
        self.messages = messages
        self.sequences = [HashableByteSequence(msg.data, hash(msg)) for msg in messages]

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    def byGoo(self):
        """original CSP algorithm for reference (see paper, Algorithm 1)"""
        L =  defaultdict(lambda: defaultdict(list))  # type: Dict[int, Dict[bytes, List[Tuple[HashableByteSequence,int]]]]
        # extract all single bytes as starting set
        for sequence in self.sequences:
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

    def byBIDEracker(self, sequences: List[HashableByteSequence] = None) \
            -> Dict[bytes, Tuple[int, Dict[HashableByteSequence, List[int]]]]:
        """
        first CSP: static fields - SF(v)

        More efficient BIDE-based alternative to the original CSP (see #byGoo()).

        We do not count subsequences per flow (see Equations 3-5 in paper;
        would not work for DHCP, DNS, ...) but for the whole trace.
        """
        MessageBIDE.MIN_SUPPORT = type(self).MIN_SUPPORT
        # we use self.messages as FlowSequenceSet and as identical MessageSequenceSet
        if sequences is None:
            sequences = self.sequences
        bide = BIDEracker(sequences)
        # BIDE returns all locally frequent values also, which we are not interested in here.
        return {k: v for k, v in bide.mostFrequent().items() if v[0] > len(sequences) * type(self).MIN_SUPPORT}

    def recursiveCSPbyBIDEracker(self):
        """
        recursive CSP for message format inference
        (see paper, Algorithm 3)
        """
        logger = logging.getLogger(__name__)
        # logger.setLevel(logging.DEBUG)
        # logger.debug("log level DEBUG")

        # needs to hold for each field:
        #    type, values (multiple ones for non-SF(v)), <-- for additional fields (Algo. 4)
        #    occurrences (seq/msg, offset) per value     <-- to generate segments afterwards
        fieldDefinitions = list()  # type: List[Field]
        # we use self.messages as MessageSequenceSet in byBIDEracker() and for recursion afterwards
        cspLevel1 = self.byBIDEracker()
        # (byteValue, occurrences) are the FieldF_i from the paper
        for byteValue, occurrences in cspLevel1.items():
            logger.debug(f"check frequent byteValue {byteValue.hex()}")
            fieldDefinitions.append(Field("SF(v)", {byteValue: occurrences}))
            posVar = type(self).posVar(occurrences)
            support = type(self).support(occurrences)
            minOffset = type(self).minOffset(occurrences)
            maxDepth = type(self).maxDepth(occurrences, len(byteValue))
            logger.debug(f"posVar {posVar:.1f} | support {support} | minOffset {minOffset} | maxDepth {minOffset}")
            if posVar <= 200 and support != 1 and maxDepth - minOffset <= 40:
                messageSequences = self.sequences
                occSeq = occurrences[1].keys()
                while True:
                    # remove the messages that contain occurrences of byteValue
                    messageSequences = type(self).removeSequences(messageSequences, occSeq)
                    messageSequences = type(self).truncateSequences(messageSequences, minOffset, maxDepth)
                    logger.debug(f"recurse CSP for {len(messageSequences)} sequences remaining")
                    cspLevelN = self.byBIDEracker(messageSequences)
                    if not cspLevelN:
                        break
                    maxSupport = max([occ[0] for bv, occ in cspLevelN.items()])
                    newValueOcc = [bvocc for bvocc in cspLevelN.items() if bvocc[1][0] == maxSupport][0]
                    if newValueOcc[0] in fieldDefinitions[-1].values:
                        fieldDefinitions[-1].values[newValueOcc[0]][1].update(newValueOcc[1][1])
                        fieldDefinitions[-1].values[newValueOcc[0]][0] += newValueOcc[1][0]
                        logger.info(f"collision: duplicate value {newValueOcc[0].hex()}")
                    fieldDefinitions[-1].values[newValueOcc[0]] = newValueOcc[1]
                    occSeq = newValueOcc[1][1].keys()
                    logger.debug(f"added occurrences for {newValueOcc[0].hex()}")
                fieldDefinitions[-1].ftype = "DF(v)"
        return fieldDefinitions

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
        return [seq for seq in byteSeq if seq not in filterList]

    @staticmethod
    def truncateSequences(byteSeq: Iterable[HashableByteSequence], offset: int, depth: int):
        """:return: A copy of the list of sequences in byteSeq without those contained in the given occurrences."""
        return [
            HashableTruncatedByteSequence(
                seq.sequence[offset:depth],
                # hash((hash(seq),offset,depth)),
                hash(seq),
                offset + seq.offset if isinstance(seq, HashableTruncatedByteSequence) else offset
            )
            for seq in byteSeq]

    @staticmethod
    def iterateOccurrences(occurrences: Tuple[int, Dict[HashableByteSequence, List[int]]]):
        for msg, offsets in occurrences[1].items():
            for o in offsets:
                yield msg, o

    def fieldDefinitions2segments(self, fieldDefinitions: List[Field]):
        logger = logging.getLogger(__name__)
        # logger.setLevel(logging.DEBUG)

        offSets = defaultdict(set)
        fieldLookup = dict()  # type: Dict[Tuple, Field]
        for field in fieldDefinitions:
            # values: Dict[bytes, Tuple[int, Dict[HashableByteSequence, List[int]]]]
            for bv, occurences in field.values.items():
                length = len(bv)
                for msg, offset in type(self).iterateOccurrences(occurences):
                    offSets[msg].add(offset)
                    offSets[msg].add(offset+length)
                    if (msg, offset) in fieldLookup:
                        logger.debug(f"Field definition of offset {offset} in message {msg} collides:\n"
                                     f"  {fieldLookup[(msg, offset)].ftype} vs. {field.ftype}")
                    fieldLookup[(msg, offset)] = field
        offLists = {msg: sorted(os) for msg, os in offSets.items()}

        # make segments from offset lists
        segList = list()
        for msg in self.messages:
            boundaryList = offLists[msg] if msg in offLists else []
            # add start and end of message if not already contained in offsets
            if len(boundaryList) == 0 or boundaryList[0] != 0:
                boundaryList = [0] + boundaryList
            if boundaryList[-1] != len(msg.data):
                boundaryList += [len(msg.data)]

            from nemere.utils.evaluationHelpers import unknown
            analyzer = Value(msg)
            segList.append([
                # type mix should be okay due to our hack of __eq__ and __hash__ in HashableByteSequence
                TypedSegment(analyzer, start, end-start,
                             fieldLookup[(msg, start)].ftype if (msg, start) in fieldLookup else unknown)
                for start, end in zip(boundaryList[:-1], boundaryList[1:])
            ])
        return segList