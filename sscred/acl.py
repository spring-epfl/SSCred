"""
The Baldimtsi-Lysyanskaya Anonymous Credentials Light scheme

Ref: Baldimtsi, Foteini, and Anna Lysyanskaya. "Anonymous credentials light."
Proceedings of the 2013 ACM SIGSAC conference on Computer & communications
security. ACM, 2013.

A guide to ACL:
1. Prove attribute knowledge: The user commits to his attributes. She/he proves
   the correctness of this commitment to the issuer with a non-interactive zkp.

2. Preparation: The issuer generates a random generator $Z1$ based on the
   commitment and randomness $rnd$ and sends $rnd$ to the user.

3. CredentialCommitment: the issuer sends an initial commitment $C$ as part of
   an interactive sigma protocol to the user.

4. CredentialChallenge: The user blinds the commitment $C$ with the randomeness
   $t$ to get a new commitment $C'$. The user computes the fiat-shamir challenge
   $\\epsilon$ based on $C'$, blinds it to $e$, and sends the blinded challenge
   to the prover.

5. CredentialResponse: The prover sends completes the sigma protocol and sends
   the response for $(C, e)$ to the user. The user unblinds the response to form
   a signature withZ $(C', \\epsilon)$.

Steps 2 and 3 can be combined together.

Warning: Running concurrent ACL signing sessions is insecure.

How to use:
    >>> # generating keys and wrappers
    >>> issuer_priv, issuer_pk = ACLParam().generate_new_key_pair()
    >>> issuer = ACLIssuer(issuer_priv, issuer_pk)
    >>> user = ACLUser(issuer_pk)
    >>> message = "Hello world"

    >>> # Issuance
    >>> attributes = [Bn(13), "Hello", "WoRlD", "Hidden"]
    >>> attr_proof = user.prove_attr_knowledge(attributes)
    >>> com, com_intern = issuer.commit(attr_proof)
    >>> challenge, challenge_intern = user.compute_blind_challenge(com, message)
    >>> resp = issuer.respond(challenge, com_intern)
    >>> cred_private = user.compute_credential(resp, challenge_internal)

    >>> # show credential
    >>> cred = cred_private.show_credential([True, True, True, False])
    >>> assert cred.verify_credential(issuer_pk)
    >>> print(cred.get_message())
    b'Hello world'
    >>> print(cred.get_attributes())
    [13, 'Hello', 'WoRlD', None]
"""
from __future__ import annotations
from typing import Collection, Tuple, Union

import attr

from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt

from .commitment import PedersenCommitment, PedersenProof
from .blind_pedersen import BlPedersenCommitment, BlPedersenPrivate, BlPedersenProof, BlindedPedersenParam
from .blind_signature import (
    AbeParam,
    AbePrivateKey,
    AbePublicKey,
    AbeSignature,
    AbeSigner,
    AbeUser,
    BlindedChallengeMessage,
    SignerCommitMessage,
    SignerCommitmentInternalState,
    SignerResponseMessage,
    UserBlindedChallengeInternalState,
)
from .config import DEFAULT_GROUP_ID


Attribute = Union[bytes, str, Bn]


class ACLAttributeProofIsInvalid(Exception):
    """The attribute proof is invalid."""


class ACLParam(AbeParam):
    """Param for ACL credential including both AbeParam and
    BlindedPedersenParam.
    """

    def __init__(self, group: EcGroup = EcGroup(DEFAULT_GROUP_ID)):
        super().__init__(group)


    def generate_new_key_pair(self) -> Tuple[ACLIssuerPrivateKey, ACLIssuerPublicKey]:
        sk = self.q.random()
        private = ACLIssuerPrivateKey(sk)
        public = private.public_key(self)
        return private, public


@attr.s(slots=True)
class ProveAttrKnowledgeMessage:
    commit = attr.ib()     # type: PedersenCommitment
    nizk_proof = attr.ib() # type: PedersenProof


class ACLIssuerPrivateKey(AbePrivateKey):
    def __init__(self, sk: Bn):
        super().__init__(sk=sk)


    def public_key(self, params: ACLParam) -> ACLIssuerPublicKey:
        """Create a public key corresponding to this private key."""
        return ACLIssuerPublicKey(params, self)


class ACLIssuerPublicKey(AbePublicKey):
    """	Use ACLParam.generate_new_key_pair to generate a fresh key pair.

    Args:
        param (ACLParam): parameters
        priv (ACLIssuerPrivateKey): issuer's private key
    """

    __slots__ = ("bc_param",)

    def __init__(self, param: ACLParam, private: ACLIssuerPrivateKey):
        super().__init__(param, private)
        # Improvement: reusing an existing param for common gens can speed up
        # the process.
        self.bc_param = BlindedPedersenParam(
            group=param.group,
            hs_size=5,
            Z=self.z,
            H_2=self.param.g
        )


    def verify_parameters(self, verify_bases: bool = False):
        """Verifies that the public key is generated correctly.

        Args:
            verify_bases (bool): if true, verifies public parameter's generators G, H
        """
        return all(
            (
                self.z == self.bc_param.Z,
                self.param.g == self.bc_param.H_2,
                super().verify_parameters(verify_bases)
            )
        )


class ACLIssuer(AbeSigner):
    """A class which handles the issuer role

    Attributes:
        private (ACLIssuerPrivateKey): issuer's private key
        public (ACLIssuerPublicKey): issuer's public key
    """

    def __init__(self, private: ACLIssuerPrivateKey, public: ACLIssuerPublicKey):
        self.private: ACLIssuerPrivateKey
        self.public: ACLIssuerPublicKey
        super().__init__(private, public)


    def commit(
            self,
            prove_attr_msg: ProveAttrKnowledgeMessage
        ) -> Tuple[SignerCommitMessage, SignerCommitmentInternalState]:
        """Checks the attribute proof and perform AbeSignature's commit phase.

        Errors:
            attribute proof is invalid
        Args:
            prove_attr_msg (ProveAttrKnowledgeMessage): the user's commitment
                to his/her values.
        Returns:
            (SignerCommitMessage)
        """

        valid_commit = prove_attr_msg.commit.verify_proof(
            pparam = self.public.bc_param,
            proof = prove_attr_msg.nizk_proof
        )
        if not valid_commit:
            raise ACLAttributeProofIsInvalid("Attribute proof is invalid.")

        commit = prove_attr_msg.commit.commit
        g = self.param.g
        return super()._commit(lambda rnd, commit=commit, g=g: commit + rnd * g)


class ACLUser(AbeUser):
    """An ACL user which receives a credential.
    This class stores a state and only supports one credential at a time.

    Attributes:
        public (ACLIssuerPublicKey): issuer's public key
    """

    __slots__ = ("user_attr_commitment", "attributes", "pcommit", "prand")

    def __init__(self, public: ACLIssuerPublicKey):
        self.public: ACLIssuerPublicKey
        super().__init__(public)


    def _compute_z1(self, rnd: Bn) -> EcPt:
        if not (isinstance(rnd, Bn) and rnd != 0 and (0 <= rnd < self.param.q)):
            raise ValueError("Invalid registration.")
        return self.user_attr_commitment.commit + rnd * self.param.g

    def compute_blind_challenge(
            self,
            commit_message: SignerCommitMessage,
            message: Union[bytes, str]
        ) -> Tuple[BlindedChallengeMessage, UserBlindedChallengeInternalState]:
        """Receive a SignerCommitMessage from the signer and start the procedure
        of getting a signature on message m from the signer.

        Args:
            commit_message (SignerCommitMessage):response from AbeSigner.commit()
            m (bytes): message to sign.
                If m is a string, then the procedure encodes it as 'utf8'
        """
        return self._compute_blind_challenge(
            commit_message,
            message,
            self._compute_z1
        )


    def prove_attr_knowledge(self, attributes: Collection[Attribute]) -> ProveAttrKnowledgeMessage:
        """ Prove the knowledge of attributes to initiate an issuance:

        Args:
            attributes (List[Union[Bn, str, bytes]]): user's attributes

        Returns:
            (ProveAttrKnowledgeMessage)
        """
        bc_param =  self.public.bc_param
        self.attributes = tuple(attributes)

        self.pcommit, self.prand = bc_param.commit(attributes)
        proof = self.pcommit.prove_knowledge(
            pparam = bc_param,
            prand = self.prand,
            values = bc_param.process_raw_values(attributes)
        )
        self.user_attr_commitment = self.pcommit
        return ProveAttrKnowledgeMessage(commit=self.pcommit, nizk_proof=proof)


    def compute_credential(
            self,
            response: SignerResponseMessage,
            challenge_state: UserBlindedChallengeInternalState
        ) -> ACLCredentialPrivate:
        """Finish the protocol and form a private credential.

        Args:
            response (SignerRespondMessage): output of ACLIssuer.respond

        Returns:
            cred_private (ACLCredentialPrivate): A private credential.
                cred_private.show_credential() creates a one time use credential
                with the private information.
        """
        sig = self.compute_signature(response, challenge_state)
        bcommit, bpriv = self.public.bc_param.blind_commit(
            raw_values=self.attributes,
            blindness_rand=challenge_state.blinder,
            h_rand=self.prand.rand
        )
        cred_private = ACLCredentialPrivate(
            signature = sig,
            bcommit = bcommit,
            bpriv = bpriv
        )
        return cred_private


class ACLCredentialPrivate:
    """An ACL credential's secret. This object can be used to generate a
    one-time use credential token

    Args:
        signature (AbeSignature): credential's signature
        bcommit (BlPedersenCommit): blind commit's public part
        bpriv (BlPedersenPrivate): blind commit's randomness
    """

    __slots__ = ("signature", "bcommit", "bpriv", "revealed")

    def __init__(self, signature: AbeSignature, bcommit: BlPedersenCommitment, bpriv: BlPedersenPrivate):
        self.signature = signature
        self.bcommit = bcommit
        self.bpriv = bpriv
        self.revealed = False


    def show_credential(self, revealed_attrs: Collection[bool]) -> ACLCredential:
        """Show the credential and reveal $revealed_attrs attributes.

        Error:
            One time use only
            revealed_attrs should have the same len as attributes.
        Args:
            revealed_attrs (boolean []): reveals attr[i] iff revealed_attrs[i]
        Returns:
            ACLCredential: a credential
        """

        if self.revealed:
            raise Exception(
                "ACL credential is one-time use only. "
                "You cannot show it twice."
            )
        self.revealed = True
        if len(revealed_attrs) != len(self.bpriv.values):
            raise Exception(
                "Revealed_attrs is a binary mask to decide which attrs "
                "should be reveal. It must have the same size as attributes."
            )

        bproof = self.bcommit.prove_values(self.bpriv, revealed_attrs)
        cred = ACLCredential(
            signature = self.signature,
            bcommit = self.bcommit,
            bc_proof = bproof
        )
        return cred


class ACLCredential:
    """An ACL credential.
    The issuer's public key is intentionally not bundled in this class to force
    the verifier to use a known correct issuer's public key.

    Attributes:
        signature (AbeSignature): credential's signature
        bcommit (BlPedersenCommit): blind commit's public part
        bc_proof (BlPedersenProof): blind commit's proof and attributes
    """

    __slots__ = ("signature", "bcommit", "bc_proof")

    def __init__(self, signature: AbeSignature, bcommit: BlPedersenCommitment, bc_proof: BlPedersenProof):
        self.signature = signature
        self.bcommit = bcommit
        self.bc_proof = bc_proof


    def verify_credential(self, issuer_pk: ACLIssuerPrivateKey) -> bool:
        """ verifies the credential. Assumes that issuer_pk and its parameters
        are verified.

        Args:
            issuer_pk (ACLIssuerPublicKey): issuer's public key.
        Returns:
            boolean: pass/fail
        """
        if not (
            issuer_pk.verify_signature(self.signature) and
            self.bcommit.verify_proof(issuer_pk.bc_param, self.bc_proof)
        ):
            return False
        return True


    def attributes(self) -> Tuple[Attribute]:
        """ get attributes.
        Returns:
            raw_attr []: raw attributes in their original format. None for
            non-revealed attributes.
        """
        return self.bc_proof.revealed_values


    def message(self) -> bytes:
        """ get message.
        Returns:
            bytes: message
        """
        return self.signature.message


def main():
    import doctest
    doctest.testmod(verbose=True)


if __name__ == "__main__":
    main()
