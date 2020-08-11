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

How to use: 
    >>> # generating keys and wrappers 
    >>> issuer_priv, issuer_pk = ACLParam().generate_new_key_pair() 
    >>> issuer = ACLIssuer(issuer_priv, issuer_pk) 
    >>> user = ACLUser(issuer_pk) 
    >>> message = "Hello world"

    >>> # Issuance
    >>> attributes = [Bn(13), "Hello", "WoRlD", "Hidden"]
    >>> attr_proof = user.prove_attr_knowledge(attributes)
    >>> com = issuer.commit(attr_proof)
    >>> challenge = user.compute_blind_challenge(com, message)
    >>> resp = issuer.respond(challenge)
    >>> cred_private = user.compute_credential(resp)

    >>> # show credential
    >>> cred = cred_private.show_credential([True, True, True, False])
    >>> assert cred.verify_credential(issuer_pk)
    >>> print(cred.get_message())
    b'Hello world'
    >>> print(cred.get_attributes())
    [13, 'Hello', 'WoRlD', None]
"""

import attr

from petlib.bn import Bn

from sscred.commitment import *
from sscred.blind_pedersen import *
from sscred.blind_signature import *
from sscred.config import DEFAULT_GROUP_ID


class ACLParam(AbeParam):
    """Param for ACL credential including both AbeParam and
    BlindedPedersenParam.
    """

    def __init__(self, group=EcGroup(DEFAULT_GROUP_ID)):
        super().__init__(group)

    def generate_new_key_pair(self):
        sk = self.q.random()
        private = ACLIssuerPrivateKey(sk)
        public = ACLIssuerPublicKey(self, private)
        return private, public


class ACLIssuerPrivateKey(AbePrivateKey):
    def __init__(self, sk):
        super().__init__(sk=sk)


class ACLIssuerPublicKey(AbePublicKey):
    def __init__(self, param, private):
        """	Use ACLParam.generate_new_key_pair to generate a fresh key pair.

        Args:
            param (ACLParam): parameters
            priv (ACLIssuerPrivateKey): issuer's private key
        """
        super().__init__(param, private)
        # Improvement: reusing an existing param for common gens can speed up 
        # the process.
        self.bc_param = BlindedPedersenParam(
            group=param.group, 
            hs_size=5,
            Z=self.Z,
            H_2=self.param.G
        )

    def verify_parameters(self, verify_bases=False):
        """Verifies that the public key is generated correctly.
        
        Args:
            verify_bases (bool): if true, verifies public parameter's generators G, H
        """
        return self.Z == self.bc_param.Z and \
               self.param.G == self.bc_param.H_2 and \
               super().verify_parameters(verify_bases)


@attr.s
class ProveAttrKnowledgeMessage(object):
    commit = attr.ib()      # type: PedersenCommitment
    nizk_proof = attr.ib()  # type: PedersenProof


############### Issuer ################
class ACLIssuer(AbeSigner):

    def __init__(self, private, public):
        """A class which handles the issuer role

        Attributes:
            private (ACLIssuerPrivateKey): issuer's private key
            public (ACLIssuerPublicKey): issuer's public key
        """
        super().__init__(private, public)

    def _compute_z1(self, rnd):
        return self.user_attr_commitment.commit + rnd * self.param.G

    def commit(self, prove_attr_msg):
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
            proof = prove_attr_msg.nizk_proof)
        if not valid_commit:
            raise Exception("Attribute proof is invalid.")
        
        self.user_attr_commitment = prove_attr_msg.commit
        return super().commit()


class ACLUser(AbeUser):
    """An ACL user which receives a credential. 
    This class stores a state and only supports one credential at a time.

    Attributes:
        public (ACLIssuerPublicKey): issuer's public key
    """

    def __init__(self, public):
        super().__init__(public)

    def _compute_z1(self, rnd):
        if not isinstance(rnd, Bn) or rnd == 0 or not (0 <= rnd < self.param.q):
            raise Exception("Invalid registration.")
        return self.user_attr_commitment.commit + rnd * self.param.G

    def prove_attr_knowledge(self, attributes):
        """ Prove the knowledge of attributes to initiate an issuance:

        Args:
            attributes (List[Union[Bn, str, bytes]]): user's attributes
        
        Returns:
            (ProveAttrKnowledgeMessage)
        """
        bc_param =  self.public.bc_param
        self.attributes = attributes
    
        self.pcommit, self.prand = bc_param.commit(attributes)
        proof = self.pcommit.prove_knowledge(
            pparam = bc_param,
            prand = self.prand, 
            values = bc_param.process_raw_values(attributes)
        )
        self.user_attr_commitment = self.pcommit
        return ProveAttrKnowledgeMessage(commit=self.pcommit, nizk_proof=proof)

    def compute_credential(self, response):
        """Finish the protocol and form a private credential.

        Args:
            response (SignerRespondMessage): output of ACLIssuer.respond

        Returns:
            cred_private (ACLCredentialPrivate): A private credential.
                cred_private.show_credential() creates a one time use credential
                with the private information.
        """
        sig = self.compute_signature(response)
        bcommit, bpriv = self.public.bc_param.blind_commit(
            raw_values=self.attributes,
            blindness_rand=self.blinder,
            h_rand=self.prand
        )
        cred_private = ACLCredentialPrivate(
            signature = sig, 
            bcommit = bcommit,
            bpriv = bpriv
        )
        return cred_private



class ACLCredentialPrivate():

    def __init__(self, signature, bcommit, bpriv):
        """An ACL credential's secret. This object can be used to generate a
        one-time use credential token

        Args:
            signature (AbeSignature): credential's signature
            bcommit (BlPedersenCommit): blind commit's public part
            bpriv (BlPedersenRand): blind commit's randomness
        """
        self.signature = signature
        self.bcommit = bcommit
        self.bpriv = bpriv
        self.revealed = False

    def show_credential(self, revealed_attrs):
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
            raise Exception("ACL credential is one-time use only. You cannot"
                " show it twice.")
        self.revealed = True
        if len(revealed_attrs) != len(self.bpriv.values):
            raise Exception("Revealed_attrs is a binary mask to decide which attrs" +
                            "should be reveal. It must have the same size as attributes.")
        
        bproof = self.bcommit.prove_values(self.bpriv, revealed_attrs)
        cred = ACLCredential(
            signature = self.signature,
            bcommit = self.bcommit,
            bc_proof = bproof
        )
        return cred


class ACLCredential():

    def __init__(self, signature, bcommit, bc_proof):
        """An ACL credential.
        The issuer's public key is intentionally not bundled in this class to force
        the verifier to use a known correct issuer's public key.

        Attributes:
            signature (AbeSignature): credential's signature
            bcommit (BlPedersenCommit): blind commit's public part
            bc_proof (BlPedersenProof): blind commit's proof and attributes
        """
        self.signature = signature
        self.bcommit = bcommit
        self.bc_proof = bc_proof

    def verify_credential(self, issuer_pk):
        """ verifies the credential. Assumes that issuer_pk and its parameters
        are verified.

        Args:
            issuer_pk (ACLIssuerPublicKey): issuer's public key.
        Returns:
            boolean: pass/fail
        """
        if not issuer_pk.verify_signature(self.signature):
            return False
        if not self.bcommit.verify_proof(issuer_pk.bc_param, self.bc_proof):
            return False
        return True

    def get_attributes(self):
        """ get attributes.
        Returns:
            raw_attr []: raw attributes in their original format. None for
            non-revealed attributes.
        """
        return self.bc_proof.revealed_values

    def get_message(self):
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
