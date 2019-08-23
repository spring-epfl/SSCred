"""
An implementation of blinded Pedersen commitment and utility support for using
it. Features: commit, blind_commit, partial open, nizk proof, verify

Examples:
	>>> values = [Bn(123), Bn(456), 'hello', b"world"]
	>>> param = BlindedPedersenParam(hs_size=len(values))
	>>> param.set_blindness_param(param.group.hash_to_point(b"bl_z"),
	... param.group.hash_to_point(b"bl_g"))

	>>> # reveal nothing
	>>> bcommit, bpriv = param.blind_commit(values)
	>>> bproof = bcommit.prove_attributes(bpriv)
	>>> assert bcommit.verify_proof(bproof)

	>>> # revealing some values
	>>> bproof2 = bcommit.prove_attributes(bpriv,
	... reveal_mask=[True, False, True, True])
	>>> assert bcommit.verify_proof(bproof2)
	>>> print(bproof2.revealed_values)
	[123, None, 'hello', b'world']

	>>> # verifying commit parameters
	>>> assert (bcommit.param.verify_parameters(
	... Z=bcommit.param.group.hash_to_point(b"bl_z"),
	... H_2=bcommit.param.group.hash_to_point(b"bl_g")))
"""

import attr

from hashlib import sha256
from petlib.bn import Bn
from petlib.ec import EcGroup

from zksk.exceptions import StatementMismatch
from zksk import Secret, DLRep

from sscred.commitment import CommitParam


def mod_range_check(x, n):
	return 0 <= x < n


@attr.s
class BlPedersenPrivate(object):
	"""A blinded Pedersen commitment's secret values.

	Attributes:
		raw_values (Bn/string/bytes): raw committed values.
		values (Secret[]): committed values.
		rand (Secret): BlPedersen's commit randomness.
		rand_2 (Secret): extra commit randomness for ACL.
		blindness_rand (Secret): blindness randomness
	"""

	raw_values = attr.ib()
	values = attr.ib()
	rand = attr.ib()
	rand_2 = attr.ib()
	blindness_rand = attr.ib()


@attr.s
class BlPedersenProof(object):
	"""A NIZK proof for knowing the values inside a BlindedPedersenCommitment

	Attributes:
		bl_h (EcPt): blindness * H
		bl_h2 (EcPt): blindness * H_2
		bl_hi (EcPt[]): blindness * HS[i]
		revealed_values (Bn []): a list of all values. If a value is not
			revealed then rv[i]=None otherwise rv[i]=open(value[i])
		proof (zksk.NIZK): zksk's nizk proof

	Reminder:
		The verifier already has bl_z and bl_commit from the commit phase
	"""
	bl_h = attr.ib()
	bl_h2 = attr.ib()
	bl_hi = attr.ib()
	revealed_values = attr.ib()
	nizk_proof = attr.ib()


class BlindedPedersenParam(CommitParam):
	""" Common parameters for blinded Pedersen.
	This class provides both vanilla and blinded Pedersen commits. The vanilla
	commit is compatible with PedersenCommitment.
	"""

	def __init__(self, group=EcGroup(713), hs_size=3):
		""" Return the common parameters for the specified curve.

		Args:
			gid: determines the elliptic curve used in the scheme.
			hs_size: maximum number of attributes allowed in the commitment.
		"""
		super(BlindedPedersenParam, self).__init__(group, hs_size)

	def verify_parameters(self, Z=None, H_2=None, valid_parameters=None):
		"""Verifies parameters. This function only checks the validity of Z
		and H_2 if the user provides a base for them. valid_parameters is
		optional and uses a valid parameter as the base to prevent unnecessary
		has_to_points and improve parent's performance.

		Args:
			Z (EcPt): valid Z base
			H_2 (EcPt): valid H_2 base
			valid_parameters (CommitParam): a valid Pedersen parameter
		Returns:
			boolean: pass/fail
		"""

		if Z is not None and Z != self.Z:
			return False
		if H_2 is not None and H_2 != self.H_2:
			return False
		return super(BlindedPedersenParam, self).verify_parameters(valid_parameters)

	def set_blindness_param(self, Z=None, H_2=None):
		"""Add the blindness generators 'Z, T' to common parameters.

		Args:
			Z (EcPt): blindness generator(z^y, C^y)
			H_2 (EcPt): Additional randomizer. Allows ACl compatibility. (Optional)
		"""
		if Z is None:
			Z = self.group.hash_to_point(b"bl_z")
		self.Z = Z
		if H_2 is None:
			H_2 = self.group.infinite()
		self.H_2 = H_2

	def process_raw_value(self, raw):
		""""process raw values.

		Args:
			raw_values (Bn mod q/string/bytes): committed value.
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
				"values can only be Bn, bytes, string, or None.")
		return Bn.from_binary(val) % self.q

	def process_raw_values(self, raw_values):
		"""process raw values.

		Args:
			raw_values (Bn mod q/string/bytes[]): committed value.
		Raises:
			Error: bad value encoding. values can only be Bn, bytes, string,
				or None.

		Returns:
			(Bn mod q []): processed value
		"""
		return [self.process_raw_value(raw) for raw in raw_values]

	def commit(self, raw_values):
		""""a vanilla Pedersen commitment to values. Encodes raw values before
		passing them to the PedersenCommitment.

		IMPORTANT: THIS FUNCTION IS NOT BLINDED.

		Args:
			raw_values (Bn mod q/string/bytes []): committed values.
		Raises:
			Error: bad value encoding. values can only be Bn, bytes, or string.
			Error: too many values

		Returns:
			PedersenCommitment: commitment
			Bn: commitment's randomness
		"""

		values = [self.process_raw_value(raw) for raw in raw_values]
		return super(BlindedPedersenParam, self).commit(values)

	def blind_commit(self, raw_values, blindness_rand=None, vanilla_prand=None):
		""""a blind commitment to values.

		Args:
			raw_values (Bn mod q/string/bytes []): committed values.
			blindness_rand (Bn mod q): forces the blinding's randomness. (optional)
			vanilla_prand (Bn): use the same H random as the
				non-blinded version. (optional)
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

		if hasattr(self, "Z") is False:
			raise Exception("There is no generator for blindness 'Z' in the parameters")

		if blindness_rand is None:
			blindness_rand = self.q.random()

		rand = self.q.random()
		if vanilla_prand is not None:
			rand = vanilla_prand
		rand_2 = self.q.random()
		C = rand * self.H + rand_2 * self.H_2
		C += self.group.wsum(values, self.HS[: len(values)])

		bl_commit = blindness_rand * C
		bl_z = blindness_rand * self.Z

		bcommit = BlPedersenCommitment(param=self, bl_z=bl_z, bl_commit=bl_commit)
		bpriv = BlPedersenPrivate(
			raw_values=raw_values,
			values=[Secret(val, name=f"val_{i}") for (i, val) in enumerate(values)],
			rand=Secret(rand, name="rand"),
			rand_2=Secret(rand_2, name="rand_2"),
			blindness_rand=Secret(blindness_rand, name="blindness_rand"),
		)

		return (bcommit, bpriv)


class BlPedersenCommitment(object):
	"""A blinded Pedersen commitment.

	Attributes:
		param (BlindedPedersenParam): parameters
		bl_commit (EcPt): randomized commitment = C ^ blindness_rand
		bl_z (EcPt): randomized Z base = Z ^ blindness_rand
	"""

	def __init__(self, param, bl_z, bl_commit):
		self.param = param
		self.bl_commit = bl_commit
		self.bl_z = bl_z

	def prove_attributes(self, bpriv, reveal_mask=None):
		"""A nizk proof for the commitment. Does not reveal any of the
		attributes.

		Args:
			bpriv (BlPedersenPrivate): attributes and randomness.
			reveal_mask (boolean []): reveals value[i] iff reveal_mask[i]
				Optional: mask=None -> reveal nothing

		Returns:
			BlPedersenProof: a nizk proof for commitment (self)
		"""

		if reveal_mask is None:
			reveal_mask = len(bpriv.values) * [False]

		# randomness
		expr_bl_z = bpriv.blindness_rand * self.param.Z
		expr_bl_h = bpriv.blindness_rand * self.param.H
		expr_bl_h2 = bpriv.blindness_rand * self.param.H_2
		bl_h, bl_h2 = expr_bl_h.eval(), expr_bl_h2.eval()

		stmt = (
			DLRep(self.bl_z, expr_bl_z) &
			DLRep(bl_h, expr_bl_h) &
			DLRep(bl_h2, expr_bl_h2)
		)

		# attributes
		bl_hi = list()
		for i in range(len(bpriv.values)):
			expr = bpriv.blindness_rand * self.param.HS[i]
			bl_hi.append(expr.eval())
			stmt = stmt & DLRep(bl_hi[i], expr)

		# proof
		revealed_values = list()
		revealed_acc = self.param.group.infinite()
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

	def verify_proof(self, bproof):
		"""Verify a PedersenProof for this commitment.
		Important: besides verifying the proof, you should verify the parameters.

		Args:
			bproof (BlPedersenProof): a nizk proof for self
		Returns:
			boolean: pass/fail
		"""

		if self.param.get_param_num() < len(bproof.bl_hi):
			self.expand_params_len(len(bproof.bl_hi))
		bl_rand_sec = Secret(name="blindness_rand")

		# randomness
		expr_bl_z = bl_rand_sec * self.param.Z
		expr_bl_h = bl_rand_sec * self.param.H
		expr_bl_h2 = bl_rand_sec * self.param.H_2
		stmt = (
			DLRep(self.bl_z, expr_bl_z) &
			DLRep(bproof.bl_h, expr_bl_h) &
			DLRep(bproof.bl_h2, expr_bl_h2)
		)

		# attributes
		for i in range(len(bproof.bl_hi)):
			expr = bl_rand_sec * self.param.HS[i]
			stmt = stmt & DLRep(bproof.bl_hi[i], expr)

		# proof

		revealed_acc = self.param.group.infinite()
		expr_bl_commit = Secret(name="rand") * bproof.bl_h + Secret(name="rand_2") * bproof.bl_h2
		for i in range(len(bproof.bl_hi)):
			if bproof.revealed_values[i] is None:
				expr_bl_commit += Secret(name=f"val_{i}") * bproof.bl_hi[i]
			else:
				val = self.param.process_raw_value(bproof.revealed_values[i])
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
