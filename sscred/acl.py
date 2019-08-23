# The Baldimtsi-Lysyanskaya Anonymous Credentials Light scheme
# ref:
# Baldimtsi, Foteini, and Anna Lysyanskaya. "Anonymous credentials light."
# Proceedings of the 2013 ACM SIGSAC conference on Computer & communications security.
# ACM, 2013.

"""
A guide to ACL
1. Prove attribute knowledge: The user commits to his attributes. He proves the
   correctness of this commitment to the signer with a interactive zkp.

2. Preparation: The signer generates a random genrator $z$ based on the
   commitment and randomness $rnd$ and sends $rnd$ to the user.

3. CredentialCommitment: the signer sends an initial commitment $C$ to the user.

4. CredentialChallenge: The user blinds the commitment $C$ with randomenes $t$
   to get a new commitment $C'$. The user computes $e$ the fiat-shamir hash
   challenge of $C'$ and sends it to the prover.

5. CredentialResponse: The prover sends the interactive zkp response of the
   initial commitment $C$ and challenge $e$. The user uses $rnd$ to adapt the
   response for $C'$ and gets a blinded signature.

How to use:
	>>> # generating keys and wrappers
	>>> signer_priv, signer_pk = ACLParam().generate_new_key_pair()
	>>> signer = ACLSigner(signer_priv, signer_pk)
	>>> user = ACLUser(signer_pk)
	>>> message = "Hello world"

	>>> # Interactive signing
	>>> attributes = [Bn(13), "Hello", "WoRlD", "Hidden"]
	>>> attr_proof = user.prove_attr_knowledge(attributes)
	>>> com = signer.commit(attr_proof)
	>>> challenge = user.compute_blind_challenge(com, message)
	>>> resp = signer.respond(challenge)
	>>> cred_private = user.compute_credential(resp)

	>>> # show credential
	>>> cred = cred_private.show_credential([True, True, True, False])
	>>> assert cred.verify_credential(signer_pk)
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


class ACLParam(AbeParam):
	"""Param for ACL credential including both AbeParam and
	BlindedPedersenParam.
	"""

	def __init__(self, group=EcGroup(713), bcommit_param=None):
		super(ACLParam, self).__init__(group)
		if bcommit_param is None:
			bcommit_param = BlindedPedersenParam(group=group, hs_size=5)
		self.bcommit_param = bcommit_param

	def generate_new_key_pair(self):
		sk = self.q.random()
		private = ACLSignerPrivateKey(sk)
		public = ACLSignerPublicKey(self, sk * self.G)
		return private, public


class ACLSignerPrivateKey(AbePrivateKey):
	def __init__(self, sk):
		super(ACLSignerPrivateKey, self).__init__(sk=sk)


class ACLSignerPublicKey(AbePublicKey):
	def __init__(self, param, public):
		super(ACLSignerPublicKey, self).__init__(param, public)


@attr.s
class ProveAttrKnowledgeMessage(object):
	commit = attr.ib()
	nizk_proof = attr.ib()


class ACLCredential(object):
	"""An ACL credential.
	The signer's public key is intentionally not bundled in this class to force
	the verifier to use a known correct signer's public key.

	Attributes:
		signature (AbeSignature): credential's signature
		bcommit (BlPedersenCommit): blind commit's public part
		bproof (BlPedersenProof): blind commit's proof and attributes
	"""

	def __init__(self, signature, bcommit, bproof):
		self.signature = signature
		self.bcommit = bcommit
		self.bproof = bproof

	def verify_credential(self, signer_pk):
		""" verifies the credential. Assumes that signer_pk and its parameters
		are verified.

		Args:
			signer_pk (ACLSignerPublicKey): signer's public key.
		Returns:
			boolean: pass/fail
		"""
		if not signer_pk.verify_signature(self.signature):
			return False
		if not self.bcommit.verify_proof(self.bproof):
			return False
		if not self.bcommit.param.verify_parameters(
			Z=signer_pk.param.Z,
			H_2=signer_pk.param.G,
			valid_parameters=signer_pk.param.bcommit_param):
			return False
		return True

	def get_attributes(self):
		""" get attributes.
		Returns:
			raw_attr []: raw attributes in their original format. None for
			non-revealed attributes.
		"""
		return self.bproof.revealed_values

	def get_message(self):
		""" get message.
		Returns:
			bytes: message
		"""
		return self.signature.message


class ACLCredentialPrivate(object):
	"""An ACL credential's secret. This object can be used to generate a
	one-time use credential token

	Attributes:
		signer_pk (ACLSignerPublicKey): signer's public key
		signature (AbeSignature): credential's signature
		bcommit (BlPedersenCommit): blind commit's public part
		bpriv (BlPedersenRand): blind commit's randomness
	"""

	def __init__(self, signer_pk, signature, bcommit, bpriv):
		self.signer_pk = signer_pk
		self.signature = signature
		self.bcommit = bcommit
		self.bpriv = bpriv
		self.revealed = False

	def show_credential(self, revealed_attrs):
		"""Show the credential and reveal $revealed_attrs attributes.

		Error:
			One time use only
		Args:
			revealed_attrs (boolean []): reveals attr[i] iff revealed_attrs[i]
		Returns:
			ACLCredential: a credential
		"""

		if self.revealed:
			raise Exception("ACL credential is one-time use only. You cannot"
				" show it twice.")
		self.revealed = True
		bproof = self.bcommit.prove_attributes(self.bpriv, revealed_attrs)
		cred = ACLCredential(signature=self.signature, bcommit=self.bcommit,
			bproof=bproof)
		return cred


############### Signer ################
class ACLSigner(AbeSigner):
	"""A class which handles the signer role

	Attributes:
		private (ACLSignerPrivateKey): signer's private key
		public (ACLSignerPublicKey): signer's public key
	"""

	def __init__(self, private, public):
		self.param = public.param
		self.public = public
		self.private = private

	def compute_z1(self, rnd):
		return self.user_attr_commitment.commit + rnd * self.param.G

	def commit(self, prove_attr_msg):
		"""Check attribute proof and perform AbeSignature's commit phase

		Errors:
			attribute proof is invalid
		Args:
			prove_attr_msg (ProveAttrKnowledgeMessage): the user's commitment
				to his/her values.
		Returns:
			SignerCommitMessage
		"""
		self.user_attr_commitment = prove_attr_msg.commit
		if not self.user_attr_commitment.verify_proof(self.param.bcommit_param,
			prove_attr_msg.nizk_proof):
			raise Exception("Attribute proof is invalid.")
		return super(ACLSigner, self).commit()


class ACLUser(AbeUser):
	"""An ACL user which receives a credential. Only one credential at a time.

	Attributes:
		public (ACLSignerPublicKey): signer's public key
	"""

	def __init__(self, public):
		self.param = public.param
		self.public = public

	def compute_z1(self, rnd):
		assert rnd > 0
		assert mod_range_check(rnd, self.param.q)
		return self.user_attr_commitment.commit + rnd * self.param.G

	def prove_attr_knowledge(self, attributes):
		self.attributes = attributes
		self.pcommit, self.prand = self.param.bcommit_param.commit(attributes)
		proof = self.pcommit.prove_attributes(self.param.bcommit_param,
			self.prand, self.param.bcommit_param.process_raw_values(attributes))
		self.user_attr_commitment = self.pcommit
		return ProveAttrKnowledgeMessage(commit=self.pcommit, nizk_proof=proof)

	def compute_credential(self, response):
		"""Finish the protocol and form a private credential.

		Args:
			cred_private (ACLCredentialPrivate): A private credential.
				cred_private.show_credential() creates a one time use credential
				with the private information.
		"""
		sig = self.compute_signature(response)
		self.param.bcommit_param.set_blindness_param(Z=self.param.Z,
			H_2=self.param.G)
		bcommit, bpriv = self.param.bcommit_param.blind_commit(
			raw_values=self.attributes,
			blindness_rand=self.blinder,
			vanilla_prand=self.prand
		)
		cred_private = ACLCredentialPrivate(signer_pk=self.public,
			signature=sig, bcommit=bcommit, bpriv=bpriv)
		return cred_private


def main():
	import doctest
	doctest.testmod(verbose=True)


if __name__ == "__main__":
	main()
