""" Adds serialization support.

This module adds 'to_binary' and 'from_binary' to AC data classes. This module
needs to be imported to access 'to_binary' and 'from_binary' functions.
Furthermore, 'packb' and 'unpackb' enable serialization of AC and petlib
classes with msgpack protocol.

Check example.py for examples
"""

import msgpack
import petlib.pack

from zksk import Secret
from zksk.base import NIZK

import sscred.acl as acl 
import sscred.commitment as commitment 
import sscred.blind_pedersen as blind_pedersen 
import sscred.blind_signature as blind_signature 

COUNTER_BASE = 20
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


def register_all_classes():
    # commitment
    add_msgpack_support(commitment.CommitParam, COUNTER_BASE+1)
    add_msgpack_support(commitment.PedersenProof, COUNTER_BASE+2)
    add_msgpack_support(commitment.PedersenCommitment, COUNTER_BASE+3)
    # blind commitment
    add_msgpack_support(blind_pedersen.BlPedersenPrivate, COUNTER_BASE+4)
    add_msgpack_support(blind_pedersen.BlPedersenProof, COUNTER_BASE+5)
    add_msgpack_support(blind_pedersen.BlindedPedersenParam, COUNTER_BASE+6)
    add_msgpack_support(blind_pedersen.BlPedersenCommitment, COUNTER_BASE+7)
    # Abe's signature
    add_msgpack_support(blind_signature.AbeParam, COUNTER_BASE+8)
    add_msgpack_support(blind_signature.AbePublicKey, COUNTER_BASE+9)
    add_msgpack_support(blind_signature.AbePrivateKey, COUNTER_BASE+10)
    add_msgpack_support(blind_signature.AbeSignature, COUNTER_BASE+11)
    add_msgpack_support(blind_signature.SignerCommitMessage, COUNTER_BASE+12)
    add_msgpack_support(blind_signature.SignerRespondMessage, COUNTER_BASE+13)
    # ACL
    add_msgpack_support(acl.ACLParam, COUNTER_BASE+14)
    add_msgpack_support(acl.ACLIssuerPrivateKey, COUNTER_BASE+15)
    add_msgpack_support(acl.ACLIssuerPublicKey, COUNTER_BASE+16)
    add_msgpack_support(acl.ProveAttrKnowledgeMessage, COUNTER_BASE+17)
    add_msgpack_support(acl.ACLCredential, COUNTER_BASE+18)
    add_msgpack_support(acl.ACLCredentialPrivate, COUNTER_BASE+19)
    # zksk
    add_msgpack_support(Secret, COUNTER_BASE+20, add_cls_methods=False)
    add_msgpack_support(NIZK, COUNTER_BASE+21, add_cls_methods=False)


register_all_classes()


def main():
    import doctest
    doctest.testmod(verbose=True)

if __name__ == '__main__':
    main()
    
