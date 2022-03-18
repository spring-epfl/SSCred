"""
An implementation of Pedersen commitment and utility support for using it.
Features: Commitment, opening, nzkp of opening

Example:
    >>> values = [Bn(2651), Bn(1), Bn(98)]
    >>> pparam = CommitParam(hs_size=len(values))
    >>> pcommit, prand = pparam.commit(values)
    >>> valid = pcommit.verify(pparam, prand, values)
    >>> print(valid)
    True
    >>> proof = pcommit.prove_knowledge(pparam, prand, values)
    >>> valid = pcommit.verify_proof(pparam, proof)
    >>> print(valid)
    True

"""

from __future__ import annotations

from hashlib import sha256
from typing import (
    Collection,
    List,
    Optional,
    Tuple,
)

import attr

from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn

from . import config


class PedersenParameters:
    """ Common parameters for Pedersen commitment."""

    def __init__(self, group: Optional[EcGroup] = None, hs_size: int = 0):
        """ Return the common parameters for the specified curve.

        Args:
            group: the elliptic curve used in the scheme.
            hs_size: generate $hs_size bases for values. expand_params_len
                allows expanding parameters.
        """
        self.group: EcGroup = EcGroup(config.DEFAULT_GROUP_ID) if group is None else group
        self.q: Bn = self.group.order()

        self.H: EcPt = self.group.hash_to_point(b"com_h")
        self.HS: List[EcPt] = list()

        self.expand_params_len(hs_size)


    def num_params(self) -> int:
        return len(self.HS)


    def __repr__(self) -> str:
        return f"<{type(self).__name__}:{self.__dict__}"


    def expand_params_len(self, hs_size: int) -> None:
        """Expand the number of available bases."""
        if hs_size <= len(self.HS):
            return

        for i in range(len(self.HS), hs_size):
            self.HS.append(self.group.hash_to_point(f'com_h{i}'.encode("utf8")))


    def verify_parameters(self, valid_parameters: Optional[PedersenParameters] = None):
        """Verifies parameters. This function always checks generators'
        randomness by reproducing the hash_to_point. valid_parameters is
        optional and uses a valid parameter as the base to prevent unnecessary
        has_to_points and improve the performance.

        Args:
            valid_parameters (CommitParam): a valid Pedersen parameter
        Returns:
            boolean: pass/fail
        """

        if valid_parameters is None:
            valid_parameters = PedersenParameters()
        valid_parameters.expand_params_len(self.num_params())

        if valid_parameters.H != self.H:
            return False

        if any(valid_parameters.HS[i] != hs for i, hs in enumerate(self.HS)):
            return False

        return True


    def commit(self, values: Collection[Bn]) -> Tuple[PedersenCommitment, PedersenRandom]:
        """"commit to values.

        Args:
            values (Bn mod q): committed values.

        Returns:
            PedersenCommitment: commitment
            PedersenRand: commitment's randomness
        """

        self.expand_params_len(len(values))

        rand: Bn = self.q.random()
        C: EcPt = rand * self.H
        C += self.group.wsum(values, self.HS[:len(values)])

        return PedersenCommitment(C), PedersenRandom(rand)


@attr.s
class PedersenRandom:
    """Pedersen commitment's random parameter."""
    rand = attr.ib() # type: Bn


@attr.s
class PedersenProof:
    """A NIZK proof for knowing the values inside a PedersenCommitment

    Attributes:
        challenge (Bn mod q): fiat-shamir challenge,
                challenge = SHA-256(pcommit, sigma_commit)
        response (Bn mod q, Bn mod q[]): sigma protocol's response values
    """
    challenge = attr.ib() # type: Bn
    response = attr.ib()  # type: Bn


class PedersenCommitment:

    def __init__(self, commit: EcPt):
        """A Pedersen commitment.

        Attributes:
            commit (EcPt): commitment's point
        """
        self.commit: EcPt = commit


    def verify(
            self,
            pparam: PedersenParameters,
            prand: PedersenRandom,
            values: Collection[Bn]
        ) -> bool:
        """Verify the commitment.

        Args:
            pparam (CommitPram): prameters
            prand (PedersenRand): commitment's secret
            values (Bn[]): commitment's values

        Returns:
            boolean: pass/fail
        """
        if len(values) > len(pparam.HS):
            raise Exception(f"parameters does not support enough {len(values)} values")

        if not pparam.group.check_point(self.commit):
            return False
        if not (0 <= prand.rand < pparam.q):
            return False

        if any((not (0 <= v < pparam.q) for v in values)):
            return False

        rhs: EcPt = prand.rand * pparam.H
        rhs += pparam.group.wsum(values, pparam.HS[:len(values)])
        return self.commit == rhs


    def prove_knowledge(
            self,
            pparam: PedersenParameters,
            prand: PedersenRandom,
            values: Collection[Bn]
        ) -> PedersenRandom:
        """ A non-interactive proof of knowledge of opening an commitment.

        Args:
            pparam (CommitPram): prameters
            prand (PedersenRand): commitment's secret
            values (Bn[]): commitment's values

        Returns:
            (PedersenProof)
        """
        # sigma protocol's commitment phase
        r_h = pparam.q.random()
        r_vs = [pparam.q.random() for _ in range(len(values))]
        R = r_h * pparam.H
        R += pparam.group.wsum(r_vs, pparam.HS[:len(r_vs)])

        # sigma protocol's challenge: Fiat-Shamir
        chash = sha256(self.commit.export() + R.export()).digest()
        e = Bn.from_binary(chash) % pparam.q

        # sigma protocol's response phase
        s_h = r_h - prand.rand * e
        s_vs = [r - x * e for (x, r) in zip(values, r_vs)]
        return PedersenProof(e, (s_h, s_vs))


    def verify_proof(self, pparam: PedersenParameters, proof: PedersenProof) -> bool:
        """Verify a PedersenProof for this commitment.

        Args:
            proof (PedersenProof): a nizk proof for self
        Returns:
            boolean: pass/fail
        """
        sigma_commit: EcPt = proof.response[0] * pparam.H
        sigma_commit += proof.challenge * self.commit
        sigma_commit += pparam.group.wsum(
            proof.response[1],
            pparam.HS[:len(proof.response[1])]
        )
        chash: bytes = sha256(self.commit.export() + sigma_commit.export()).digest()
        h: Bn = Bn.from_binary(chash) % pparam.q

        return h == proof.challenge


def main():
    import doctest
    doctest.testmod(verbose=True)


if __name__ == '__main__':
    main()
