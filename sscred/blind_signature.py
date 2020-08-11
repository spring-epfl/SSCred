"""
Abe's blind signature scheme
Ref: # Abe, M. A Secure Three-move Blind Signature Scheme for Polynomially
Many Signatures.

An implementation of Abe's blind signature. An user 'AbeUser' asks a signer
'AbeSigner' to sign a message 'message' without revealing its content.

The parameters' names follow the Abe's paper notation.

Naming convention: Variables denoting EcPt are named with a capital letter
while scalar variables start with a small letter.

Example:
    >>> # generating keys and wrappers
    >>> priv, pk = AbeParam().generate_new_key_pair()
    >>> signer = AbeSigner(priv, pk)
    >>> user = AbeUser(pk)
    >>> message = "Hello world"
    >>> # Interactive signing
    >>> com = signer.commit()
    >>> challenge = user.compute_blind_challenge(com, message)
    >>> resp = signer.respond(challenge)
    >>> sig = user.compute_signature(resp)
    >>> # Verifying the signature
    >>> assert pk.verify_signature(sig)
    >>> print(sig.message)
    b'Hello world'
"""

import attr

from petlib.bn import Bn
from petlib.ec import EcPt
from hashlib import sha256

from sscred.commitment import *
from sscred.config import DEFAULT_GROUP_ID

class AbeParam():
    """Param for ACL and commitments"""

    def __init__(self, group=EcGroup(DEFAULT_GROUP_ID)):
        self.group = group                          # type: Bn
        self.q = self.group.order()                 # type: Bn
        self.G = self.group.hash_to_point(b"sig_g") # type: EcPt
        self.H = self.group.hash_to_point(b"sig_h") # type: EcPt

    def generate_new_key_pair(self):
        sk = self.q.random()
        private = AbePrivateKey(sk)
        public = AbePublicKey(self, private)
        return private, public


@attr.s
class AbeSignature():
    message = attr.ib() # type: Union[bytes, str]
    Zeta = attr.ib()    # type: EcPt
    Zeta1 = attr.ib()   # type: EcPt
    rho = attr.ib()     # type: Bn
    w = attr.ib()       # type: Bn
    delta1 = attr.ib()  # type: Bn
    delta2 = attr.ib()  # type: Bn
    sigma = attr.ib()   # type: Bn
    micro = attr.ib()   # type: Bn


@attr.s
class SignerCommitMessage():
    rnd = attr.ib() # type: Bn
    A = attr.ib()   # type: EcPt
    B1 = attr.ib()  # type: EcPt
    B2 = attr.ib()  # type: EcPt


@attr.s
class SignerRespondMessage():
    r = attr.ib()  # type: Bn
    c = attr.ib()  # type: Bn
    s1 = attr.ib() # type: Bn
    s2 = attr.ib() # type: Bn
    d = attr.ib()  # type: Bn


@attr.s
class AbePrivateKey():
    sk = attr.ib() # type: Bn


class AbePublicKey():

    def __init__(self, param, priv):
        """Use AbeParam.generate_new_key_pair to generate a fresh key pair.

        Attributes:
            param (AbeParam): parameters
            priv (AbePrivateKey): signer's private key
        """
        self.param = param              # type: AbeParam
        self.PK = priv.sk * param.G     # type: EcPt
        self.Z = self._compute_z_param()

    def _compute_z_param(self):
        return self.param.group.hash_to_point(
            self.param.G.export() + self.param.H.export() + self.PK.export()
        )

    def verify_parameters(self, verify_bases=False):
        """Verifies that the public key is generated correctly.
        
        Args:
            verify_bases (bool): if true, verifies public parameter's generators G, H
        """
        if verify_bases:
            if self.param.G != self.Z.group.hash_to_point(b"sig_g"):
                return False
            if self.param.H != self.Z.group.hash_to_point(b"sig_h"):
                return False
        return self.Z == self._compute_z_param()

    def verify_signature(self, sig):
        """verifies the correctness of the signature

        Args:
            sig (AbeSignature): the signature
        """

        param = self.param
        try:
            # check sig's variables range
            assert param.group.check_point(sig.Zeta)
            assert param.group.check_point(sig.Zeta1)
            assert (0 <= sig.rho < param.q)
            assert (0 <= sig.w < param.q)
            assert (0 <= sig.delta1 < param.q)
            assert (0 <= sig.delta2 < param.q)
            assert (0 <= sig.sigma < param.q)
            assert (0 <= sig.micro < param.q)

        except Exception as e:
            return False

        if not isinstance(sig.message, bytes):
            return False

        if sig.Zeta.is_infinite():
            return False

        sig.Zeta2 = sig.Zeta - sig.Zeta1
        h = sha256(b'||'.join(
            [sig.Zeta.export(),
            sig.Zeta1.export(),
            (sig.rho * param.G + sig.w * self.PK).export(),
            (sig.delta1 * param.G + sig.sigma * sig.Zeta1).export(),
            (sig.delta2 * param.H + sig.sigma * sig.Zeta2).export(),
            (sig.micro * self.Z + sig.sigma * sig.Zeta).export(),
            sig.message]
        )).digest()

        lhs = (sig.w + sig.sigma) % param.q
        rhs = Bn.from_binary(h) % param.q

        return lhs == rhs


############### Signer ################
class AbeSigner():
    """A class which handles the signer role.
    
    Warning: This class can only sign one message at a time. 
    In other words, It keeps state between commit and response, which does noy
    work with concurrent comits. You can create multiple signers with the same
    public key.
    """

    def __init__(self, private, public):
        """Creates a new AbeSigner.

        Args:
            private (AbePrivateKey): signer's private key
            public (AbePublicKey): signer's public key
        """
        self.param = public.param
        self.public = public
        self.private = private

    def _compute_z1(self, rnd):
        return self.param.group.hash_to_point(b"z1_" + rnd.binary())

    def commit(self):
        """Initiate the signing protocol.

        Returns:
            (SignerCommitMessage)
        """
        self.rnd = self.param.q.random()
        self.Z1 = self._compute_z1(self.rnd)
        self.Z2 = self.public.Z - self.Z1

        self.u, self.s1, self.s2, self.d = (
            self.param.q.random() for __ in range(4)
        )
        self.A = self.u * self.param.G
        self.B1 = self.s1 * self.param.G + self.d * self.Z1
        self.B2 = self.s2 * self.param.H + self.d * self.Z2

        return SignerCommitMessage(self.rnd, self.A, self.B1, self.B2)

    def respond(self, e):
        """Compute the response for the user's challenge.

        Args:
            e (Bn): The user's blinded challenge 
        Returns:
            (SignerRespondMessage)
        """
        c = (e - self.d) % self.param.q
        r = (self.u - c * self.private.sk) % self.param.q

        return SignerRespondMessage(r, c, self.s1, self.s2, self.d)


class AbeUser():

    def __init__(self, public, verify_pk=False):
        """Creates a new user.

        Attributes:
            public (AbePublicKey): signer's public key
        """
        self.param = public.param
        self.public = public
        if verify_pk and not self.public.verify_parameters():
            raise Exception("Invalid public key")

    # duplicate of Abe.Signer.compute_z1
    def _compute_z1(self, rnd):
        return self.param.group.hash_to_point(b"z1_" + rnd.binary())

    def compute_blind_challenge(self, commit_message, m):
        """Receive a SignerCommitMessage from the signer and start the procedure
        of getting a signature on message m from the signer.

        Args:
            commit_message (SignerCommitMessage):response from AbeSigner.commit()
            m (bytes): message to sign.
                If m is a string, then the procedure encodes it as 'utf8'
        """
        self.rnd = commit_message.rnd
        self.Z1 = self._compute_z1(self.rnd)
        self.Z2 = self.public.Z - self.Z1
        self.A, self.B1, self.B2 = (
            commit_message.A,
            commit_message.B1,
            commit_message.B2,
        )

        if isinstance(m, str):
            m = m.encode('utf8')
        if not isinstance(m, bytes):
            raise Exception("Bad encoding in message")
        self.message = m

        assert self.param.group.check_point(self.A)
        assert self.param.group.check_point(self.B1)
        assert self.param.group.check_point(self.B2)

        self.blinder = self.param.q.random()
        self.tau = self.param.q.random()
        self.Eta = self.tau * self.public.Z

        self.Zeta = self.blinder * self.public.Z
        self.Zeta1 = self.blinder * self.Z1
        self.Zeta2 = self.Zeta - self.Zeta1

        self.t = [self.param.q.random() for __ in range(5)]

        self.Alpha = self.A + self.t[0] * self.param.G + self.t[1] * self.public.PK
        self.Beta1 = (
            self.blinder * self.B1 + self.t[2] * self.param.G + self.t[3] * self.Zeta1
        )
        self.Beta2 = (
            self.blinder * self.B2 + self.t[4] * self.param.H + self.t[3] * self.Zeta2
        )

        h = sha256(b'||'.join(
            [self.Zeta.export(),
            self.Zeta1.export(),
            self.Alpha.export(),
            self.Beta1.export(),
            self.Beta2.export(),
            self.Eta.export(),
            self.message]
        )).digest()
        self.epsilon = Bn.from_binary(h) % self.param.q

        self.e = (self.epsilon - self.t[1] - self.t[3]) % self.param.q
        return self.e

    def compute_signature(self, response):
        """Finish the blind signing's sigma protocol and form a signature

        Args:
            response (SignerRespondMessage): output of AbeSigner.respond
        Returns:
            AbeSignature: a signature which can be verified agains the signer's
            public key
        """
        self.rho = (response.r + self.t[0]) % self.param.q
        self.w = (response.c + self.t[1]) % self.param.q
        self.delta1 = (self.blinder * response.s1 + self.t[2]) % self.param.q
        self.delta2 = (self.blinder * response.s2 + self.t[4]) % self.param.q
        self.sigma = (response.d + self.t[3]) % self.param.q
        self.micro = (self.tau - self.sigma * self.blinder) % self.param.q
        sig = AbeSignature(
            self.message,
            self.Zeta,
            self.Zeta1,
            self.rho,
            self.w,
            self.delta1,
            self.delta2,
            self.sigma,
            self.micro,
        )
        return sig


def main():
    import doctest
    doctest.testmod(verbose=True)


if __name__ == "__main__":
    main()
