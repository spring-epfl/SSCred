"""
An implementation of blinded Pedersen commitment and utility support for using
it. Features: commit, blind_commit, partial open, nizk proof, verify

Examples:
    >>> values = [Bn(123), Bn(456), 'hello', b"world"]
    >>> param = BlindedPedersenParam(hs_size=len(values))

    >>> # reveal nothing
    >>> bcommit, bpriv = param.blind_commit(values)
    >>> bproof = bcommit.prove_values(bpriv)
    >>> assert bcommit.verify_proof(param, bproof)

    >>> # revealing some values
    >>> bproof = bcommit.prove_values(bpriv, reveal_mask=[True, False, True, True])
    >>> assert bcommit.verify_proof(param, bproof)
    >>> print(bproof.revealed_values)
    [123, None, 'hello', b'world']
"""

from hashlib import sha256
from typing import List, Optional, Union

import attr

from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt

from zksk import Secret, DLRep
from zksk.base import NIZK
from zksk.exceptions import StatementMismatch

from .commitment import PedersenParameters


class BlindedPedersenParam(PedersenParameters):
    """ Common parameters for blinded Pedersen.
    This class provides both vanilla and blinded Pedersen commits. The vanilla
    commit is compatible with PedersenCommitment.
    """

    def __init__(self, group: Optional[EcGroup] = None, hs_size=3, Z=None, H_2=None):
        """ Return the common parameters for the specified curve.

        Z and H_2 are intended for compatibilities between SSCred submodules.
        The ACL submodule uses these two arguments to customize the commitment.
        For standalone use of the commitment, leave Z and H_2 empty.

        Args:
            group (EcGroup): determines the elliptic curve used in the scheme.
            hs_size (int): maximum number of attributes allowed in the commitment.
            Z (EcPt): blindness generator(z^y, C^y) (Optional)
            H_2 (EcPt): Additional randomizer. Allows ACl compatibility. (Optional)
        """
        super().__init__(group, hs_size)
        self.Z = Z if Z is not None else self.group.hash_to_point(b"bl_z")
        self.H_2 = H_2 if H_2 is not None else self.group.infinite()

    def process_raw_value(self, raw):
        """"process raw values.

        Args:
            raw_values (int, Bn mod q/string/bytes): committed value.
        Raises:
            Error: bad value encoding. values can only be Bn, bytes, string,
                or None.
        Returns:
            (Bn mod q): processed value
        """
        val = None
        if raw is None:
            return None
        elif isinstance(raw, Bn):
            return raw
        elif isinstance(raw, bytes):
            val = sha256(raw).digest()
        elif isinstance(raw, str):
            val = sha256(raw.encode('utf8')).digest()
        elif isinstance(raw, int):
            return Bn(raw)
        else:
            raise Exception("Bad commitment value encoding."
                "values can only be int, Bn, bytes, string, or None.")
        return Bn.from_binary(val) % self.q


    def process_raw_values(self, raw_values):
        """process raw values.

        Args:
            raw_values (int, Bn mod q/string/bytes[]): committed value.
        Raises:
            Error: bad value encoding. values can only be Bn, bytes, string,
                or None.

        Returns:
            (Bn mod q []): processed value
        """
        return [self.process_raw_value(raw) for raw in raw_values]


    def commit(self, raw_values):
        """"A non-blinded Pedersen commitment to values. Encodes raw values before
        passing them to the PedersenCommitment.

        IMPORTANT: THIS FUNCTION IS NOT BLINDED.

        Args:
            raw_values (Bn mod q/string/bytes []): committed values.
        Raises:
            Error: bad value encoding. values can only be Bn, bytes, or string.
            Error: too many values

        Returns:
            (PedersenCommitment): commitment
            (PedersenRand): commitment's randomness
        """

        values = [self.process_raw_value(raw) for raw in raw_values]
        return super(BlindedPedersenParam, self).commit(values)


    def blind_commit(self, raw_values, blindness_rand=None, h_rand=None):
        """"a blind commitment to values.

        Arguments blindness_rand and h_rand enable ACL compatability.

        Args:
            raw_values (Bn mod q/string/bytes []): committed values.
            blindness_rand (Bn mod q): forces the blinding's randomness. (optional)
            h_rand (Bn): fix the randomness for H. (optional)
        Raises:
            Error: bad value encoding. values can only be Bn, bytes, or string.
            Error: blindness generator is unknown

        Returns:
            BlPedersenCommitment: commitment
            BlPedersenPrivate: commitment's values and randomness
        """

        values = [self.process_raw_value(raw) for raw in raw_values]

        if len(values) > len(self.HS):
            self.expand_params_len(len(values))

        rand = h_rand if h_rand is not None else self.q.random()

        rand_2 = self.q.random()
        if blindness_rand is None:
            blindness_rand = self.q.random()

        C = (rand * self.H) + (rand_2 * self.H_2)
        C += self.group.wsum(values, self.HS[: len(values)])

        bl_commit = blindness_rand * C
        bl_z = blindness_rand * self.Z

        bcommit = BlPedersenCommitment(bl_z=bl_z, bl_commit=bl_commit)
        bpriv = BlPedersenPrivate(
            param=self,
            raw_values=list(raw_values),
            values=[Secret(val, name=f"val_{i}") for (i, val) in enumerate(values)],
            rand=Secret(rand, name="rand"),
            rand_2=Secret(rand_2, name="rand_2"),
            blindness_rand=Secret(blindness_rand, name="blindness_rand"),
        )

        return (bcommit, bpriv)


@attr.s
class BlPedersenPrivate():
    """A blinded Pedersen commitment's secret values.

    Attributes:
        param (BlindedPedersenParam): commitment parameters
        raw_values (Union[Bn,string,bytes]): raw committed values.
        values (Secret[]): committed values.
        rand (Secret): BlPedersen's commit randomness.
        rand_2 (Secret): extra commit randomness for ACL.
        blindness_rand (Secret): blindness randomness
    """
    param = attr.ib()          # type: BlindedPedersenParam
    raw_values = attr.ib()     # type: Union[Bn,str,bytes]
    values = attr.ib()         # type: List[Secret]
    rand = attr.ib()           # type: Secret
    rand_2 = attr.ib()         # type: Secret
    blindness_rand = attr.ib() # type: Secret


@attr.s
class BlPedersenProof():
    """A NIZK proof of knowing the opening of a BlindedPedersenCommitment.

    Attributes:
        bl_h (EcPt): blindness for H
        bl_h2 (EcPt): blindness for H_2
        bl_hi (EcPt[]): blindness for HS[i]
        revealed_values (Bn []): a list of all values. If a value is not
            revealed then rv[i]=None, otherwise rv[i]=open(value[i])
        proof (zksk.NIZK): zksk's nizk proof

    Reminder:
        The verifier already has bl_z and bl_commit from the commit phase
    """
    bl_h = attr.ib()              # type: EcPt
    bl_h2 = attr.ib()             # type: EcPt
    bl_hi = attr.ib()             # type: EcPt
    revealed_values = attr.ib()   # type: List[Bn]
    nizk_proof = attr.ib()        # type: NIZK


class BlPedersenCommitment:
    """The public commitment in a blinded Pedersen commitment"""

    def __init__(self, bl_z, bl_commit):
        """Create a blinded Pedersen commitment.

        Attributes:
            bl_commit (EcPt): randomized commitment = C ^ blindness_rand
            bl_z (EcPt): randomized Z base = Z ^ blindness_rand
        """
        self.bl_commit = bl_commit
        self.bl_z = bl_z

    def prove_values(self, bpriv, reveal_mask=None):
        """A nizk proof of opening with the revealed values.
        The proof contains the raw value of all revealed values. This protocol
        does not reveal any information about non-revealed values.

        Error:
            Either reveal_mask should be None or have the same size of private values.
        Args:
            bpriv (BlPedersenPrivate): values and randomness.
            reveal_mask (boolean []): reveals value[i] iff reveal_mask[i]
                Optional: mask=None -> reveal nothing

        Returns: (BlPedersenProof): a nizk proof for commitment (self)
        """
        param = bpriv.param
        if reveal_mask is None:
            reveal_mask = len(bpriv.values) * [False]
        if len(reveal_mask) != len(bpriv.values):
            raise Exception('The size of reveal mask does not match the number of attributes')

        # randomness
        expr_bl_z = bpriv.blindness_rand * param.Z
        expr_bl_h = bpriv.blindness_rand * param.H
        expr_bl_h2 = bpriv.blindness_rand * param.H_2
        bl_h, bl_h2 = expr_bl_h.eval(), expr_bl_h2.eval()

        stmt = (
            DLRep(self.bl_z, expr_bl_z) &
            DLRep(bl_h, expr_bl_h) &
            DLRep(bl_h2, expr_bl_h2)
        )

        # attributes
        bl_hi = list()
        for i in range(len(bpriv.values)):
            expr = bpriv.blindness_rand * param.HS[i]
            bl_hi.append(expr.eval())
            stmt = stmt & DLRep(bl_hi[i], expr)

        # proof
        revealed_values = list()
        revealed_acc = param.group.infinite()
        expr_bl_commit = bpriv.rand * bl_h + bpriv.rand_2 * bl_h2
        for i in range(len(bpriv.values)):
            if reveal_mask[i]:
                revealed_values.append(bpriv.raw_values[i])
                revealed_acc += bpriv.values[i].value * bl_hi[i]
            else:
                revealed_values.append(None)
                expr_bl_commit += bpriv.values[i] * bl_hi[i]
        stmt = stmt & DLRep(self.bl_commit - revealed_acc, expr_bl_commit)
        bproof = BlPedersenProof(
            bl_h=bl_h,
            bl_h2=bl_h2,
            bl_hi=bl_hi,
            revealed_values=revealed_values,
            nizk_proof=stmt.prove()
        )
        return bproof

    def verify_proof(self, bc_param, bproof):
        """Verify a PedersenProof for this commitment.
        Important: besides verifying the proof, you should verify the parameters.

        Args:
            bc_param (BlPedersenParam): commitment parameters
            bproof (BlPedersenProof): a nizk proof for self
        Returns:
            boolean: pass/fail
        """

        if bc_param.num_params() < len(bproof.bl_hi):
            bc_param.expand_params_len(len(bproof.bl_hi))
        bl_rand_sec = Secret(name="blindness_rand")

        # randomness
        expr_bl_z = bl_rand_sec * bc_param.Z
        expr_bl_h = bl_rand_sec * bc_param.H
        expr_bl_h2 = bl_rand_sec * bc_param.H_2
        stmt = (
            DLRep(self.bl_z, expr_bl_z) &
            DLRep(bproof.bl_h, expr_bl_h) &
            DLRep(bproof.bl_h2, expr_bl_h2)
        )

        # attributes
        for i in range(len(bproof.bl_hi)):
            expr = bl_rand_sec *bc_param.HS[i]
            stmt = stmt & DLRep(bproof.bl_hi[i], expr)

        # proof
        revealed_acc = bc_param.group.infinite()
        expr_bl_commit = Secret(name="rand") * bproof.bl_h + Secret(name="rand_2") * bproof.bl_h2
        for i in range(len(bproof.bl_hi)):
            if bproof.revealed_values[i] is None:
                expr_bl_commit += Secret(name=f"val_{i}") * bproof.bl_hi[i]
            else:
                val = bc_param.process_raw_value(bproof.revealed_values[i])
                revealed_acc += val * bproof.bl_hi[i]
        stmt = stmt & DLRep(self.bl_commit - revealed_acc, expr_bl_commit)

        # Having an invalid revealed secret leads to different
        # {commit-revealed_acc} value between prover and verifier. Since this
        # value is a zksk.statement constant, the mismatch results in a
        # StatementMismatch exception. verify_proof checks for this exception
        # and convert it to False
        try:
            is_valid = stmt.verify(bproof.nizk_proof)
        except StatementMismatch:
            return False
        return is_valid


def main():
    import doctest
    doctest.testmod(verbose=True)


if __name__ == "__main__":
    main()
