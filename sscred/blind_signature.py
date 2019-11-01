"""
Abe's blind signature scheme
ref: # Abe, M. A Secure Three-move Blind Signature Scheme for Polynomially
Many Signatures.

An implementation for Abe's blind signature. An user 'AbeUser' asks a signer
'AbeSigner' to sign a message 'message' without revealing its content.

Naming convention: Variables denoting EcPt are named with a capital letter
while scalar variables start with a small letter

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


def mod_range_check(x, n):
	return 0 <= x < n


class AbeParam(object):
	"""Param for ACL and commitments"""

	def __init__(self, group=EcGroup(713)):
		self.group = group
		self.q = self.group.order()
		self.G = self.group.hash_to_point(b"sig_g")
		self.H = self.group.hash_to_point(b"sig_h")

	def compute_tag_public_key(self, public):
		""" Compute Z param

		Args:
			public (AbePublicKey): signer's public key
		"""
		self.Z = self.group.hash_to_point(
			self.G.export() + self.H.export() + public.PK.export()
		)

	def generate_new_key_pair(self):
		sk = self.q.random()
		private = AbePrivateKey(sk)
		public = AbePublicKey(self, sk * self.G)
		return private, public

	def verify_parameters(self, signer_pk, valid_param=None):
		"""verifies abe's parameters. signer_pk is necessary to compute Z base.
		valid_param is optional and it improves the performance of the check.

		Args:
			signer_pk (AbePublicKey): signer's public key
			valid_param (AbeParam): a verified abe parameter (optional)
		"""
		if valid_param is None:
			valid_param = AbeParam(group=signer_pk.PK.group)
		if not hasattr(valid_param, 'Z'):
			valid_param.compute_tag_public_key(signer_pk)
		if valid_param.G != self.G:
			return False
		if valid_param.H != self.H:
			return False
		if valid_param.Z != self.Z:
			return False
		return True


@attr.s
class AbeSignature(object):
	message = attr.ib()
	Zeta = attr.ib()
	Zeta1 = attr.ib()
	rho = attr.ib()
	w = attr.ib()
	delta1 = attr.ib()
	delta2 = attr.ib()
	sigma = attr.ib()
	micro = attr.ib()


@attr.s
class SignerCommitMessage(object):
	rnd = attr.ib()
	A = attr.ib()
	B1 = attr.ib()
	B2 = attr.ib()


@attr.s
class SignerRespondMessage(object):
	r = attr.ib()
	c = attr.ib()
	s1 = attr.ib()
	s2 = attr.ib()
	d = attr.ib()


@attr.s
class AbePrivateKey(object):
	sk = attr.ib()


class AbePublicKey(object):
	"""AbeSignatures public key

	Attributes:
		param (AbeParam): parameters
		PK (EcPt): signer's public key
	"""

	def __init__(self, param, pk):
		self.param = param
		self.PK = pk
		self.param.compute_tag_public_key(self)

	def verify_parameters(self, valid_param=None):
		return self.param.verify_parameters(signer_pk=self, valid_param=valid_param)

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
			assert mod_range_check(sig.rho, param.q)
			assert mod_range_check(sig.w, param.q)
			assert mod_range_check(sig.delta1, param.q)
			assert mod_range_check(sig.delta2, param.q)
			assert mod_range_check(sig.sigma, param.q)
			assert mod_range_check(sig.micro, param.q)

		except Exception as e:
			raise e
			return False

		if not isinstance(sig.message, bytes):
			return False

		sig.Zeta2 = sig.Zeta - sig.Zeta1
		h = sha256(
			sig.Zeta.export()
			+ sig.Zeta1.export()
			+ (sig.rho * param.G + sig.w * self.PK).export()
			+ (sig.delta1 * param.G + sig.sigma * sig.Zeta1).export()
			+ (sig.delta2 * param.H + sig.sigma * sig.Zeta2).export()
			+ (sig.micro * param.Z + sig.sigma * sig.Zeta).export()
			+ sig.message
		).digest()

		lhs = (sig.w + sig.sigma) % param.q
		rhs = Bn.from_binary(h) % param.q

		return lhs == rhs


############### Signer ################
class AbeSigner(object):
	"""A class which handles the signer role

	Attributes:
		private (AbePrivateKey): signer's private key
		public (AbePublicKey): signer's public key
	"""

	def __init__(self, private, public):
		self.param = public.param
		self.public = public
		self.private = private

	def compute_z1(self, rnd):
		return self.param.group.hash_to_point(b"z1_" + rnd.binary())

	def commit(self):
		self.rnd = self.param.q.random()
		self.Z1 = self.compute_z1(self.rnd)
		self.Z2 = self.param.Z - self.Z1

		self.u, self.s1, self.s2, self.d = (
			self.param.q.random() for __ in range(4)
		)
		self.A = self.u * self.param.G
		self.B1 = self.s1 * self.param.G + self.d * self.Z1
		self.B2 = self.s2 * self.param.H + self.d * self.Z2

		return SignerCommitMessage(self.rnd, self.A, self.B1, self.B2)

	def respond(self, e):
		c = (e - self.d) % self.param.q
		r = (self.u - c * self.private.sk) % self.param.q

		return SignerRespondMessage(r, c, self.s1, self.s2, self.d)


class AbeUser(object):
	"""docstring for User

	Attributes:
		public (AbePublicKey): signer's public key
	"""

	def __init__(self, public):
		self.param = public.param
		self.public = public
		# if not self.param.verify_parameters(public):
		# 	raise Exception("Invalid public key")

	# duplicate of Abe.Signer.compute_z1
	def compute_z1(self, rnd):
		assert rnd > 0
		assert mod_range_check(rnd, self.param.q)
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
		self.Z1 = self.compute_z1(self.rnd)
		self.Z2 = self.param.Z - self.Z1
		self.A, self.B1, self.B2 = (
			commit_message.A,
			commit_message.B1,
			commit_message.B2,
		)

		self.message = m
		if isinstance(self.message, str):
			self.message = self.message.encode('utf8')
		if not isinstance(self.message, bytes):
			raise Exception("Bad encoding in message")

		assert self.param.group.check_point(self.A)
		assert self.param.group.check_point(self.B1)
		assert self.param.group.check_point(self.B2)

		self.blinder = self.param.q.random()
		self.tau = self.param.q.random()
		self.Eta = self.tau * self.param.Z

		self.Zeta = self.blinder * self.param.Z
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

		h = sha256(
			self.Zeta.export()
			+ self.Zeta1.export()
			+ self.Alpha.export()
			+ self.Beta1.export()
			+ self.Beta2.export()
			+ self.Eta.export()
			+ self.message
		).digest()
		self.epsilon = Bn.from_binary(h) % self.param.q

		self.e = (self.epsilon - self.t[1] - self.t[3]) % self.param.q
		return self.e

	def compute_signature(self, response):
		"""Finish the blind signing's sigma protocol and form a signature

		Args:
			response (SignerRespondMessage): out put of AbeSigner.respond
		Returns:
			AbeSignature: a signature which can be verified with signer's public
			key
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

# def example():
# 	# generating keys and wrappers
# 	priv, pk = AbeParam().generate_new_key_pair()
# 	signer = AbeSigner(priv, pk)
# 	user = AbeUser(pk)
# 	message = "Hello world"
# 	# Interactive signing
# 	com = signer.commit()
# 	challenge = user.compute_blind_challenge(com, message)
# 	resp = signer.respond(challenge)
# 	sig = user.compute_signature(resp)
# 	# Verifying the signature
# 	assert pk.verify_signature(sig)
	# print(sig.message)


def main():
	import doctest
	doctest.testmod(verbose=True)


if __name__ == "__main__":
	main()
