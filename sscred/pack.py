""" Adds serialization support.

This module adds 'to_binary' and 'from_binary' to AC data classes. This module
needs to be imported to access 'to_binary' and 'from_binary' functions.
Furthermore, 'packb' and 'unpackb' enable serialization of AC and petlib
classes with msgpack protocol.

Check example.py for examples
"""

import msgpack
import petlib.pack


from . import blind_signature

COUNTER_BASE = 20
_pack_reg = dict()


def packb(obj):
    """packs a serializable object with msgpack"""
    return msgpack.packb(obj, default=_default, use_bin_type=True)


def unpackb(data):
    """unpacks a serialized object with msgpack"""
    return msgpack.unpackb(data, ext_hook=petlib.pack.ext_hook, raw=False)


def _default(obj, enable_inherited_classes=False):
    """Overwriting petlib's default to allow inheritance between packable classes.

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



def add_msgpack_support_slots(cls, ext, add_cls_methods=True):
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
        return packb({key: getattr(obj, key) for key in obj.__slots__})

    def dec(data):
        obj = cls.__new__(cls)
        for key, value in unpackb(data).items():
            if key != "__weakref__":
                setattr(obj, key, value)
        return obj

    def eq(a, b):
        if type(a) != type(b):
            return NotImplemented
        for ka, kb in zip(a.__slots__, b.__slots__):
            if getattr(a, ka) != getattr(b, kb):
                return False
        return True

    if add_cls_methods:
        if cls.__eq__ is object.__eq__:
            cls.__eq__ = eq
        cls.to_bytes = enc
        cls.from_bytes = staticmethod(dec)

    _pack_reg[cls] = (ext, enc)
    petlib.pack.register_coders(cls, ext, enc, dec)


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
    # Abe's signature
    add_msgpack_support_slots(blind_signature.AbeParam, COUNTER_BASE+8)
    add_msgpack_support_slots(blind_signature.AbePublicKey, COUNTER_BASE+9)
    add_msgpack_support_slots(blind_signature.AbePrivateKey, COUNTER_BASE+10)
    add_msgpack_support_slots(blind_signature.AbeSignature, COUNTER_BASE+11)
    add_msgpack_support_slots(blind_signature.SignerCommitMessage, COUNTER_BASE+12)
    add_msgpack_support_slots(blind_signature.SignerResponseMessage, COUNTER_BASE+13)

    # Added later
    add_msgpack_support_slots(blind_signature.SignerCommitmentInternalState, COUNTER_BASE+22)
    add_msgpack_support_slots(blind_signature.UserBlindedChallengeInternalState, COUNTER_BASE+23)
    add_msgpack_support_slots(blind_signature.BlindedChallengeMessage, COUNTER_BASE+24)

register_all_classes()


def main():
    import doctest
    doctest.testmod(verbose=True)

if __name__ == '__main__':
    main()

