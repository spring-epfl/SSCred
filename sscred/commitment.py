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
import attr

from hashlib import sha256
from petlib.ec import EcGroup
from petlib.bn import Bn

from sscred.config import DEFAULT_GROUP_ID


class CommitParam():
    """ Common parameters for Pedersen commitment."""

    def __init__(self, group=EcGroup(DEFAULT_GROUP_ID), hs_size=0):
        """ Return the common parameters for the specified curve.

        Args:
            group: the elliptic curve used in the scheme.
            hs_size: generate $hs_size bases for values. expand_params_len
                allows expanding parameters.
        """
        self.group = group
        self.q = self.group.order()

        self.H = self.group.hash_to_point(b"com_h")
        self.HS = list()
        self.expand_params_len(hs_size)

    def __repr__(self):
        return (f'<{type(self).__name__}:{self.__dict__}')

    def expand_params_len(self, hs_size):
        """Expand the number of available bases."""
        if hs_size <= len(self.HS):
            return
        for i in range(len(self.HS), hs_size):
            self.HS.append(self.group.hash_to_point(("com_h%s" % i).encode("utf8")))

    def get_param_num(self):
        return len(self.HS)

    def verify_parameters(self, valid_parameters=None):
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
            valid_parameters = CommitParam()
        valid_parameters.expand_params_len(self.get_param_num())

        if valid_parameters.H != self.H:
            return False
        for i in range(self.get_param_num()):
            if valid_parameters.HS[i] != self.HS[i]:
                return False
        return True

    def commit(self, values):
        """"commit to values.

        Args:
            values (Bn mod q): committed values.

        Returns:
            PedersenCommitment: commitment
            PedersenRand: commitment's randomness
        """

        if len(values) > len(self.HS):
            self.expand_params_len(len(values))

        rand = self.q.random()
        C = rand * self.H
        C += self.group.wsum(values, self.HS[:len(values)])

        pcommit = PedersenCommitment(C)
        return pcommit, rand


@attr.s
class PedersenProof():
    """A NIZK proof for knowing the values inside a PedersenCommitment

    Attributes:
        challenge (Bn mod q): fiat-shamir challenge,
                challenge = SHA-256(pcommit, sigma_commit)
        response (Bn mod q, Bn mod q[]): sigma protocol's response values
    """
    challenge = attr.ib()
    response = attr.ib()


class PedersenCommitment():

    def __init__(self, commit):
        """A Pedersen commitment.

        Attributes:
            commit (EcPt): commitment's point
        """
        self.commit = commit

    def verify(self, pparam, prand, values):
        """Verify the commitment.

        Args:
            pparam (CommitPram): prameters
            prand (PedersenRand): commitment's secret
            values (Bn[]): commitment's values

        Returns:
            boolean: pass/fail
        """
        C = self.commit
        r, values = prand, values

        if len(values) > len(pparam.HS):
            raise Exception(f"parameters does not support enough {len(values)} values")

        if not pparam.group.check_point(C):
            return False
        if not (0 <= r < pparam.q):
            return False
        for v in values:
            if not (0 <= v < pparam.q):
                return False

        rhs = r * pparam.H
        rhs += pparam.group.wsum(values, pparam.HS[:len(values)])
        return C == rhs

    def prove_knowledge(self, pparam, prand, values):
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
        s_h = r_h - prand * e
        s_vs = [r - x * e for (x, r) in zip(values, r_vs)]
        return PedersenProof(e, (s_h, s_vs))

    def verify_proof(self, pparam, proof):
        """Verify a PedersenProof for this commitment.

        Args:
            proof (PedersenProof): a nizk proof for self
        Returns:
            boolean: pass/fail
        """
        sigma_commit = proof.response[0] * pparam.H
        sigma_commit += proof.challenge * self.commit
        sigma_commit += pparam.group.wsum(proof.response[1],
            pparam.HS[:len(proof.response[1])])
        chash = sha256(self.commit.export() + sigma_commit.export()).digest()
        h = Bn.from_binary(chash) % pparam.q
        return h == proof.challenge


def main():
    import doctest
    doctest.testmod(verbose=True)


if __name__ == '__main__':
    main()
