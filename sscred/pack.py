""" Adds serialization support.

This module adds 'to_binary' and 'from_binary' to AC data classes. This module
needs to be imported to access 'to_binary' and 'from_binary' functions.
Furthermore, 'packb' and 'unpackb' enable serialization of AC and petlib
classes with msgpack protocol.

example:
	>>> values = [Bn(123), Bn(456), 'hello', b"world"]
	>>> param = BlindedPedersenParam(hs_size=len(values))
	>>> param.set_blindness_param(param.group.hash_to_point(b"bl_z"),
	...   param.group.hash_to_point(b"bl_g"))
	>>> bcommit, bpriv = param.blind_commit(values)

	>>> bt = param.to_binary()
	>>> param_2 = BlindedPedersenParam.from_binary(bt)
	>>> # param does not support equality
	>>> assert type(param) == type(param_2)
	>>> assert param.__dict__ == param_2.__dict__

	>>> bt = packb((bcommit, bpriv))
	>>> bcommit_2, bpriv_2 = unpackb(bt)
	>>> # commitment does not support equality
	>>> assert type(bcommit) == type(bcommit_2)
	>>> assert bpriv == bpriv_2
"""
import msgpack
import petlib.pack

from zksk import Secret

from sscred.acl import *
from sscred.commitment import *
from sscred.blind_pedersen import *
from sscred.blind_signature import *


_pack_reg = dict()


def packb(obj):
	"""packs a serializable object with msgpack"""
	return msgpack.packb(obj, default=_default, use_bin_type=True)


def unpackb(data):
	"""unpacks a serialized object with msgpack"""
	return msgpack.unpackb(data, ext_hook=petlib.pack.ext_hook, raw=False)


def _default(obj, enable_inherited_classes=False):
	""" Overwriting petlib's default to allow inheritance between packable classes.

	This function packs obj with type(obj)'s packer. If enable_inherited_classes
	is true, the function checks for parent classed with a pack method if an
	exact match fails. enable_inherited_classes is only useful if you extend
	classes in AC without explicitly adding add_msgpack_support. Otherwise it
	reduces the performance.
	"""

	# check exact type to prevent calling parent's packing when the child has
	# defined a packer.
	if type(obj) in _pack_reg:
		num, enc = _pack_reg[type(obj)]
		return msgpack.ExtType(num, enc(obj))

	# allow packing inherited classes without explicit packing method
	# this lowers the performance
	if enable_inherited_classes:
		for T in _pack_reg:
			if isinstance(obj, T):
				num, enc = _pack_reg[T]
				return msgpack.ExtType(num, enc(obj))

	return petlib.pack.default(obj)


def add_msgpack_support(cls, ext, add_cls_methods=True):
	"""Adds serialization support,

	Enables packing and unpacking with msgpack with 'pack.packb' and
	'pack.unpackb' methods.

	If add_method then enables equality, reading and writing for the classs.
	Specificly, adds methods:
		bytes   <- obj.to_binary()
		obj     <- cls.from_binary(bytes)
		boolean <- obj1 == obj2

	Args:
		cls: class
		ext: an unique code for the msgpack's Ext hook
	"""
	def enc(obj):
		return packb(obj.__dict__)

	def dec(data):
		obj = cls.__new__(cls)
		obj.__dict__.update(unpackb(data))
		return obj

	def eq(a, b):
		if type(a) != type(b):
			return NotImplemented
		return a.__dict__ == b.__dict__

	if add_cls_methods:
		if cls.__eq__ is object.__eq__:
			cls.__eq__ = eq
		cls.to_bytes = enc
		cls.from_bytes = staticmethod(dec)

	_pack_reg[cls] = (ext, enc)
	petlib.pack.register_coders(cls, ext, enc, dec)


def main():
	import doctest
	doctest.testmod(verbose=True)


# commitment
add_msgpack_support(CommitParam, 11)
add_msgpack_support(PedersenProof, 12)
add_msgpack_support(PedersenCommitment, 13)
# blind commitment
add_msgpack_support(BlPedersenPrivate, 14)
add_msgpack_support(BlPedersenProof, 15)
add_msgpack_support(BlindedPedersenParam, 16)
add_msgpack_support(BlPedersenCommitment, 17)
# Abe's signature
add_msgpack_support(AbeParam, 18)
add_msgpack_support(AbePublicKey, 19)
add_msgpack_support(AbePrivateKey, 20)
add_msgpack_support(AbeSignature, 21)
add_msgpack_support(SignerCommitMessage, 22)
add_msgpack_support(SignerRespondMessage, 23)
# ACL
add_msgpack_support(ACLParam, 24)
add_msgpack_support(ACLSignerPrivateKey, 25)
add_msgpack_support(ACLSignerPublicKey, 26)
add_msgpack_support(ProveAttrKnowledgeMessage, 27)
add_msgpack_support(ACLCredential, 28)
add_msgpack_support(ACLCredentialPrivate, 29)
# zksk
add_msgpack_support(Secret, 30, add_cls_methods=False)


if __name__ == '__main__':
	main()
