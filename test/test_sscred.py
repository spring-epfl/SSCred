from typing import Union
import pytest

from petlib.bn import Bn

from sscred.blind_signature import *
from sscred.config import DEFAULT_GROUP_ID
from sscred.pack import packb, unpackb, add_msgpack_support


def auto_sign(signer: AbeSigner, user: AbeUser, message: Union[bytes, str]) -> AbeSignature:
    m1, p1 = signer.commit()
    m2, p2 = user.compute_blind_challenge(m1, message)
    m3 = signer.respond(m2, p1)
    sig = user.compute_signature(m3, p2)
    return sig


def test_abe_signature_verification():
    priv, pk = AbeParam().generate_new_key_pair()

    # To ensure that signer's previous signature's state does not corrupt future
    # queries if used in an iterative way.
    signer = AbeSigner(priv, pk)
    user = AbeUser(pk)
    for i in range(1, 10):
        message = f"Hello world{i}"
        sig = auto_sign(signer, user, message)
        assert pk.verify_signature(sig)
        assert message.encode('utf8') == sig.message


def test_abe_signature_concurrent_fail_if_acl_is_enabled():
    priv, pk = AbeParam().generate_new_key_pair()
    signer = AbeSigner(priv, pk, disable_acl=False)

    signer.commit()
    with pytest.raises(AbeSignerStateInvalid):
        signer.commit()


def test_abe_signature_concurrent_fail_if_acl_is_disabled():
    priv, pk = AbeParam().generate_new_key_pair()
    signer = AbeSigner(priv, pk, disable_acl=True)

    signer.commit()
    signer.commit()


def test_abe_signature_verification_corrupted():
    priv, pk = AbeParam().generate_new_key_pair()
    priv2, pk2 = AbeParam().generate_new_key_pair()
    message = "Hello world"

    # verifying against wrong public key
    signer = AbeSigner(priv, pk)
    user = AbeUser(pk)
    sig = auto_sign(signer, user, message)
    assert not pk2.verify_signature(sig)

    # wrong secret key
    signer = AbeSigner(priv2, pk)
    user = AbeUser(pk)
    sig = auto_sign(signer, user, message)
    assert not pk.verify_signature(sig)

    # wrong public key for the user
    signer = AbeSigner(priv, pk)
    user = AbeUser(pk2)
    sig = auto_sign(signer, user, message)
    assert not pk.verify_signature(sig)
    assert not pk2.verify_signature(sig)

def test_pack_cls():
    @attr.s
    class CLS(object):
        a = attr.ib()
        b = attr.ib()
    add_msgpack_support(CLS, 10)

    obj = CLS(a=[3, 'asd', Bn(123)], b=EcGroup().generator())
    obj2 = CLS(a=False, b=11 * EcGroup().generator())
    d = obj.to_bytes()
    objp = CLS.from_bytes(d)
    assert obj == objp

    x = [obj, obj2]
    bt = packb(x)
    xp = unpackb(bt)
    assert x == xp


def test_pack_blind_sig():
    priv, pk = AbeParam().generate_new_key_pair()
    signer = AbeSigner(priv, pk)
    user = AbeUser(pk)
    message = "Hello world"
    com, signer_params = signer.commit()
    challenge, user_params = user.compute_blind_challenge(com, message)
    resp = signer.respond(challenge, signer_params)
    sig = user.compute_signature(resp, user_params)

    m1 = packb(com)
    m2 = packb(challenge)
    m3 = packb(resp)
    m4 = packb(sig)
    m5 = packb(priv)
    m6 = packb(pk)

    assert unpackb(m1) == com
    assert unpackb(m2) == challenge
    assert unpackb(m3) == resp
    assert unpackb(m4) == sig
    assert unpackb(m5) == priv
    assert unpackb(m6) == pk


def main():
    pass


if __name__ == '__main__':
    main()
