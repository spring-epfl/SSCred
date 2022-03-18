"""
Abe's blind signature scheme
Ref: # Abe, M. A Secure Three-move Blind Signature Scheme for Polynomially
Many Signatures.

An implementation of Abe's blind signature. An user 'AbeUser' asks a signer
'AbeSigner' to sign a message 'message' without revealing its content.

The parameters' names follow the Abe's paper notation.

Example:
    >>> # generating keys and wrappers
    >>> priv, pk = AbeParam().generate_new_key_pair()
    >>> signer = AbeSigner(priv, pk)
    >>> user = AbeUser(pk)
    >>> message = b"Hello world"
    >>> # Interactive signing
    >>> com, com_intern = signer.commit()
    >>> challenge, challenge_intern = user.compute_blind_challenge(com, message)
    >>> resp = signer.respond(challenge, com_intern)
    >>> sig = user.compute_signature(resp, challenge_intern)
    >>> # Verifying the signature
    >>> assert pk.verify_signature(sig)
    >>> print(sig.message)
    b'Hello world'
"""

from __future__ import annotations

from enum import IntEnum
from hashlib import sha256
from threading import Lock
from typing import (
    Callable,
    List,
    Optional,
    Tuple,
    Union,
)

import attr
from petlib.bn import Bn
from petlib.ec import (
    EcPt,
    EcGroup,
)

from . import config


class AbeSignerStateInvalid(Exception):
    """The Abe signer is in an invalid state."""


class AbePublicKeyInvalid(Exception):
    """The public key for Abe's blind signature scheme is invalid."""


class AbeSignerState(IntEnum):
    """State of the Abe signer."""
    COMMITTED = 0
    READY_TO_COMMIT = 1


class AbeParam:
    """Parameters for Abe's blind signature scheme.

    :param group: elliptic curve to use for the blind signature
    """

    __slots__ = ("group", "q", "g", "h")

    def __init__(self, group: Optional[EcGroup] = None) -> None:
        self.group: EcGroup = EcGroup(config.DEFAULT_GROUP_ID) if group is None else group
        self.q: Bn = self.group.order()
        self.g: EcPt = self.group.hash_to_point(b"sig_g")
        self.h: EcPt = self.group.hash_to_point(b"sig_h")


    def generate_new_key_pair(self) -> Tuple[AbePrivateKey, AbePublicKey]:
        """Generate a new key pair for Abe's blind signature.

        :return: a tuple containing a private key and its corresponding public key
        """
        sk: Bn = self.q.random()
        private = AbePrivateKey(sk)
        public = private.public_key(self)
        return private, public


@attr.s(slots=True)
class AbeSignature:
    message = attr.ib() # type: Union[bytes, str]
    zeta = attr.ib()    # type: EcPt
    zeta1 = attr.ib()   # type: EcPt
    rho = attr.ib()     # type: Bn
    w = attr.ib()       # type: Bn
    delta1 = attr.ib()  # type: Bn
    delta2 = attr.ib()  # type: Bn
    sigma = attr.ib()   # type: Bn
    micro = attr.ib()   # type: Bn


@attr.s(slots=True)
class SignerCommitMessage:
    rnd = attr.ib() # type: Bn
    a = attr.ib()   # type: EcPt
    b1 = attr.ib()  # type: EcPt
    b2 = attr.ib()  # type: EcPt


@attr.s(slots=True)
class SignerCommitmentInternalState:
    u = attr.ib()  # type: Bn
    s1 = attr.ib() # type: Bn
    s2 = attr.ib() # type: Bn
    d = attr.ib()  # type: Bn

    @classmethod
    def new(cls, q: Bn) -> SignerCommitmentInternalState:
        """Generate a new set of random internal parameters."""
        return cls(*(q.random() for _ in range(4)))


@attr.s(slots=True)
class BlindedChallengeMessage:
    e = attr.ib() # type: Bn


@attr.s(slots=True)
class UserBlindedChallengeInternalState:
    blinder = attr.ib() # type: Bn
    tau = attr.ib()     # type: Bn
    t = attr.ib()       # type: List[Bn]
    zeta = attr.ib()    # type: EcPt
    zeta1 = attr.ib()   # type: EcPt
    message = attr.ib() # type: bytes


@attr.s(slots=True)
class SignerResponseMessage:
    r = attr.ib()  # type: Bn
    c = attr.ib()  # type: Bn
    s1 = attr.ib() # type: Bn
    s2 = attr.ib() # type: Bn
    d = attr.ib()  # type: Bn


@attr.s(slots=True)
class AbePrivateKey:
    sk = attr.ib() # type: Bn

    def public_key(self, params: Optional[AbeParam] = None) -> AbePublicKey:
        """Create a public key corresponding to this private key."""
        if params is None:
            params = AbeParam()
        return AbePublicKey(params, self)


class AbePublicKey:
    """Public key for Abe's blind signature scheme.

    :param param: parameters
    :param priv: signer's private key
    """

    __slots__ = ("param", "pk", "z")


    def __init__(self, param: AbeParam, priv: AbePrivateKey) -> None:
        self.param: AbeParam = param
        self.pk: EcPt = priv.sk * param.g
        self.z: EcPt = self._compute_z_param()


    def _compute_z_param(self) -> EcPt:
        return self.param.group.hash_to_point(
            self.param.g.export() + self.param.h.export() + self.pk.export()
        )


    def verify_parameters(self, verify_bases: bool = False) -> bool:
        """Verify that the public key is valid.

        :param verify_bases: verifies public parameter's generators G and H
        :return: True if the public key is valid, False otherwise
        """
        if verify_bases:
            if self.param.g != self.z.group.hash_to_point(b"sig_g"):
                return False
            if self.param.h != self.z.group.hash_to_point(b"sig_h"):
                return False
        return self.z == self._compute_z_param()


    def verify_signature(self, sig: AbeSignature) -> bool:
        """Verify that the signature is valid

        :param sig: the signature to verify
        :return: True if the signature is valid, False otherwise
        """

        param: AbeParam = self.param

        if not all((
            param.group.check_point(sig.zeta),
            param.group.check_point(sig.zeta1),
            (0 <= sig.rho < param.q),
            (0 <= sig.w < param.q),
            (0 <= sig.delta1 < param.q),
            (0 <= sig.delta2 < param.q),
            (0 <= sig.sigma < param.q),
            (0 <= sig.micro < param.q),
            isinstance(sig.message, bytes),
            not sig.zeta.is_infinite(),
        )):
            return False

        zeta2: EcPt = sig.zeta - sig.zeta1
        h = sha256(
            b'||'.join((
                sig.zeta.export(),
                sig.zeta1.export(),
                (sig.rho * param.g + sig.w * self.pk).export(),
                (sig.delta1 * param.g + sig.sigma * sig.zeta1).export(),
                (sig.delta2 * param.h + sig.sigma * zeta2).export(),
                (sig.micro * self.z + sig.sigma * sig.zeta).export(),
                sig.message,
            ))
        ).digest()

        lhs: Bn = (sig.w + sig.sigma) % param.q
        rhs: Bn = Bn.from_binary(h) % param.q

        return lhs == rhs


class AbeSigner:
    """Signer for Abe's blind signature scheme

    **Warning:** When used for Anonymous credentials light (ACL), commitments can not be issued in
    parallel. Instead, the signer and the user have to issue commitment and respond back a blinded
    challenge sequentially. Therefore the signer can not issue a new commitment until the user
    responded to the previous commitment.

    By default the signer will ensure it can not issue a commitment until the previous one was
    responded correctly, and these checks are thread safe. Optionally, you can disable the thread
    safety meachanism if you prefer to implement it at a higher level, or completely disable the
    safety checks if you do not intent to use the signer for ACL.

    :param private: signer's private key
    :param public: signer's public key
    :param disable_acl: disable check to ensure ACL validity
    :param thread_safe: ensure the signer is thread safe (parameter ignored when ACL usage is
        disabled)
    """

    __slots__ = ("param", "public", "private", "enable_acl", "state", "lock")

    def __init__(
            self,
            private: AbePrivateKey,
            public: AbePublicKey,
            disable_acl: bool = False,
            thread_safe: bool = True
        ) -> None:
        self.param: AbeParam = public.param
        self.public: AbePublicKey = public
        self.private: AbePrivateKey = private
        self.enable_acl: bool = not disable_acl
        self.state: AbeSignerState = AbeSignerState.READY_TO_COMMIT
        self.lock: Lock = Lock() if self.enable_acl and thread_safe else None


    def commit(self) -> Tuple[SignerCommitMessage, SignerCommitmentInternalState]:
        """Initiate the signing protocol.

        :raises AbeSignerStateInvalid: The signer attempted to issue a new commitment before
            receiving a blinded challenge for the previous one.
        :return: a tuple containing a commitment message and the commitment's internal parameters
            that will be necessary to process the user's blinded challenge to this commitment
        """
        group = self.param.group
        return self._commit(lambda rnd, group=group: group.hash_to_point(b"z1_" + rnd.binary()))


    def _commit(
            self,
            compute_z1: Callable[[Bn], EcPt]
        ) -> Tuple[SignerCommitMessage, SignerCommitmentInternalState]:

        if self.enable_acl:
            if self.lock is not None:
                self.lock.acquire()
            if self.state != AbeSignerState.READY_TO_COMMIT:
                raise AbeSignerStateInvalid(
                    "Can not make a new commitment until a blinded challenge is received for the "
                    "previous one."
                )

        rnd: Bn = self.param.q.random()
        z1: EcPt = compute_z1(rnd)
        z2: EcPt = self.public.z - z1

        rnd_params = SignerCommitmentInternalState.new(self.param.q)

        a: EcPt = rnd_params.u * self.param.g
        b1: EcPt = rnd_params.s1 * self.param.g + rnd_params.d * z1
        b2: EcPt = rnd_params.s2 * self.param.h + rnd_params.d * z2

        if self.enable_acl:
            self.state = AbeSignerState.COMMITTED
            if self.lock is not None:
                self.lock.release()

        return (
            SignerCommitMessage(rnd, a, b1, b2),
            rnd_params,
        )


    def respond(
            self,
            challenge: BlindedChallengeMessage,
            commit_state: SignerCommitmentInternalState
        ) -> SignerResponseMessage:
        """Compute the response for the user's challenge.

        :param challenge: the user's blinded challenge
        :param internal_params: internal parameters of the commitment to which the user responded
            with this blinded challenge
        :raises AbeSignerStateInvalid: The signer attempted to respond to a blinded challenge
            before issuing a commitment.
        :return: response to the blinded message
        """
        if self.enable_acl:
            if self.lock is not None:
                self.lock.acquire()
            if self.state != AbeSignerState.COMMITTED:
                raise AbeSignerStateInvalid(
                    "Attempt to respond to a commitment which has not been issued."
                )

        c: Bn = (challenge.e - commit_state.d) % self.param.q
        r: Bn = (commit_state.u - c * self.private.sk) % self.param.q

        if self.enable_acl:
            self.state = AbeSignerState.READY_TO_COMMIT
            if self.lock is not None:
                self.lock.release()

        return SignerResponseMessage(
            r,
            c,
            commit_state.s1,
            commit_state.s2,
            commit_state.d
        )


class AbeUser:
    """User for Abe's blind signature scheme.

    :param public: signer's public key
    :param verify_pk: verify the signer's public key
    :raises AbePublicKeyInvalid: The public key is invalid
    """

    __slots__ = ("param", "public")

    def __init__(self, public: AbePublicKey, verify_pk: bool = False):
        self.param: AbeParam = public.param
        self.public: AbePublicKey = public
        if verify_pk and not self.public.verify_parameters():
            raise AbePublicKeyInvalid()


    def compute_blind_challenge(
            self,
            commit_message: SignerCommitMessage,
            message: Union[bytes, str]
        ) -> Tuple[BlindedChallengeMessage, UserBlindedChallengeInternalState]:
        """Compute a blind challenge with a commitment from teh signer and a message to sign.

        :param commit_message: commitment from the signer
        :param message: a message to sign
        :raises ValueError: The commitment or the message to sign is invalid.
        :return: a tuple containing a blind challenge to respond back to the signer and the blind
            challenge's internal parameters that will be necessary to process the signer's response
            to this blind challenge
        """
        group = self.param.group
        return self._compute_blind_challenge(
            commit_message,
            message,
            lambda rnd, group=group: group.hash_to_point(b"z1_" + rnd.binary())
        )


    def _compute_blind_challenge(
            self,
            commit_message: SignerCommitMessage,
            message: Union[bytes, str],
            compute_z1: Callable[[Bn], EcPt]
        ) -> Tuple[BlindedChallengeMessage, UserBlindedChallengeInternalState]:
        if isinstance(message, str):
            message = message.encode('utf8')
        if not isinstance(message, bytes):
            raise ValueError("Invalid message, 'message' is not bytes")

        rnd: Bn = commit_message.rnd
        z1: EcPt = compute_z1(rnd)

        a: EcPt
        b1: EcPt
        b2: EcPt
        a, b1, b2 = (
            commit_message.a,
            commit_message.b1,
            commit_message.b2,
        )

        if not self.param.group.check_point(a):
            raise ValueError("Invalid point A")
        if not self.param.group.check_point(b1):
            raise ValueError("Invalid point B1")
        if not self.param.group.check_point(b2):
            raise ValueError("Invalid point B2")

        blinder: Bn = self.param.q.random()
        tau: Bn = self.param.q.random()
        t: List[Bn] = [self.param.q.random() for _ in range(5)]
        zeta: EcPt = blinder * self.public.z
        zeta1: EcPt = blinder * z1

        eta: EcPt = tau * self.public.z
        zeta2: EcPt = zeta - zeta1

        alpha: EcPt = a + t[0] * self.param.g + t[1] * self.public.pk
        beta1: EcPt = blinder * b1 + t[2] * self.param.g + t[3] * zeta1
        beta2: EcPt = blinder * b2 + t[4] * self.param.h + t[3] * zeta2

        h: bytes = sha256(b'||'.join(
            (
                zeta.export(),
                zeta1.export(),
                alpha.export(),
                beta1.export(),
                beta2.export(),
                eta.export(),
                message
            )
        )).digest()

        epsilon: Bn = Bn.from_binary(h) % self.param.q

        e: Bn = (epsilon - t[1] - t[3]) % self.param.q
        return (
            BlindedChallengeMessage(e),
            UserBlindedChallengeInternalState(blinder, tau, t, zeta, zeta1, message)
        )


    def compute_signature(
            self,
            response: SignerResponseMessage,
            challenge_state: UserBlindedChallengeInternalState
        ) -> AbeSignature:
        """Finish the blind signing's sigma protocol and compute a signature

        :param response: signer's response to the blind challenge
        :param challenge_private: internal parameters of the blind challenge to which the signer
            responded.
        :return: a signature which can be verified agains the signer's public key
        """
        rho: Bn = (response.r + challenge_state.t[0]) % self.param.q
        w: Bn = (response.c + challenge_state.t[1]) % self.param.q
        delta1: Bn = (challenge_state.blinder * response.s1 + challenge_state.t[2]) % self.param.q
        delta2: Bn = (challenge_state.blinder * response.s2 + challenge_state.t[4]) % self.param.q
        sigma: Bn = (response.d + challenge_state.t[3]) % self.param.q
        micro: Bn = (challenge_state.tau - sigma * challenge_state.blinder) % self.param.q

        return AbeSignature(
            challenge_state.message,
            challenge_state.zeta,
            challenge_state.zeta1,
            rho,
            w,
            delta1,
            delta2,
            sigma,
            micro,
        )


def main():
    import doctest
    doctest.testmod(verbose=True)


if __name__ == "__main__":
    main()
