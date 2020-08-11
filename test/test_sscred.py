import pytest

from petlib.bn import Bn

from sscred.commitment import *
from sscred.blind_signature import *
from sscred.blind_pedersen import *
from sscred.acl import *
from sscred.config import DEFAULT_GROUP_ID
from sscred.pack import packb, unpackb, add_msgpack_support


def test_pedersen_commit_verification():
    values = [Bn(2651), Bn(1), Bn(98)]
    pparam = CommitParam(hs_size=len(values))
    assert pparam.verify_parameters()
    pcommit, prand = pparam.commit(values)
    assert pcommit.verify(pparam, prand, values)


def test_pedersen_commit_proof():
    values = [Bn(2651), Bn(1), Bn(98)]
    pparam = CommitParam(hs_size=len(values))
    pcommit, prand = pparam.commit(values)
    proof = pcommit.prove_knowledge(pparam, prand, values)
    assert pcommit.verify_proof(pparam, proof)


def test_pedersen_commit_invalid_proof():
    values = [Bn(2651), Bn(1), Bn(98)]
    pparam = CommitParam(hs_size=len(values))
    pcommit, prand = pparam.commit(values)
    prand = pparam.q.random()
    assert not pcommit.verify(pparam, prand, values)
    proof = pcommit.prove_knowledge(pparam, prand, values)
    assert not pcommit.verify_proof(pparam, proof)


def auto_sign(signer, user, message):
    m1 = signer.commit()
    m2 = user.compute_blind_challenge(m1, message)
    m3 = signer.respond(m2)
    sig = user.compute_signature(m3)
    return sig


def test_abe_signature_verification():
    priv, pk = AbeParam().generate_new_key_pair()
    signer = AbeSigner(priv, pk)

    # To ensure that signer's previous signature's state does not corrupt future
    # queries
    for i in range(1, 10):
        user = AbeUser(pk)
        message = f"Hello world{i}"
        sig = auto_sign(signer, user, message)
        assert pk.verify_signature(sig)
        assert message.encode('utf8') == sig.message


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


def test_bl_pedersen_valid():
    values = [Bn(123), Bn(456), 'hello', b"world"]
    param = BlindedPedersenParam(hs_size=len(values))

    # reveal nothing
    bcommit, bpriv = param.blind_commit(values)
    bproof = bcommit.prove_values(bpriv)
    assert bcommit.verify_proof(param, bproof)

    # revealing some values
    bproof2 = bcommit.prove_values(bpriv, reveal_mask=[True, False, True, True])
    assert bcommit.verify_proof(param, bproof2)
    assert bproof2.revealed_values == [Bn(123), None, 'hello', b"world"]


def test_bl_pedersen_with_acl_params_valid():
    group = EcGroup(DEFAULT_GROUP_ID)
    g1 = group.hash_to_point(b"test_z")
    g2 = group.hash_to_point(b"test_h2")

    values = [Bn(123), Bn(456), 'hello', b"world"]
    param = BlindedPedersenParam(hs_size=len(values), Z=g1, H_2=g2 )
    bcommit, bpriv = param.blind_commit(values)

    bproof = bcommit.prove_values(bpriv, reveal_mask=[True, False, True, True])
    assert bcommit.verify_proof(param, bproof)
    assert bproof.revealed_values == [Bn(123), None, 'hello', b"world"]


def test_bl_pedersen_invalid():
    group = EcGroup(DEFAULT_GROUP_ID)
    g1 = group.hash_to_point(b"test_z")
    g2 = group.hash_to_point(b"test_h2")

    values = [Bn(123), Bn(456), 'hello', b"world"]
    param = BlindedPedersenParam(hs_size=len(values), Z=g1, H_2=g2)
    bcommit, bpriv = param.blind_commit(values)

    # corrupt rand
    bpriv2 = unpackb(packb(bpriv))
    bpriv2.rand.value = param.q.random()
    bproof = bcommit.prove_values(bpriv2, reveal_mask=[True, False, True, True])
    assert not bcommit.verify_proof(param, bproof)

    # corrupt rand2
    bpriv3 = unpackb(packb(bpriv))
    bpriv3.rand_2.value = param.q.random()
    bproof = bcommit.prove_values(bpriv3, reveal_mask=[True, False, True, True])
    assert not bcommit.verify_proof(param, bproof)

    # corrupt blindness
    bpriv4 = unpackb(packb(bpriv))
    bpriv4.blindness_rand.value = param.q.random()
    bproof = bcommit.prove_values(bpriv4, reveal_mask=[True, False, True, True])
    assert not bcommit.verify_proof(param, bproof)

    # corrupt revealed value
    # This leads to different zksk.statement constants between prover and
    # verifier which result in StatementMismatch exception. verify_proof checks
    # for this statement and convert it to False
    bpriv5 = unpackb(packb(bpriv))
    bpriv5.values[0].value = param.q.random()
    bproof = bcommit.prove_values(bpriv5, reveal_mask=[True, False, True, True])
    assert not bcommit.verify_proof(param, bproof)

    # corrupt hidden value
    bpriv6 = unpackb(packb(bpriv))
    bpriv6.values[1].value = param.q.random()
    bproof = bcommit.prove_values(bpriv6, reveal_mask=[True, False, True, True])
    assert not bcommit.verify_proof(param, bproof)


def auto_cred(user, issuer, attrs):
    # Interactive signing
    message = "This isn't a test message."
    m0 = user.prove_attr_knowledge(attrs)
    m1 = issuer.commit(m0)
    m2 = user.compute_blind_challenge(m1, message)
    m3 = issuer.respond(m2)
    return user.compute_credential(m3)


def test_acl_valid():
    # generating keys and wrappers
    issuer_priv, issuer_pk = ACLParam().generate_new_key_pair()
    issuer = ACLIssuer(issuer_priv, issuer_pk)
    user = ACLUser(issuer_pk)

    attrs = [Bn(13), "Hello", "WoRlD", "Hidden"]
    cred_private = auto_cred(user, issuer, attrs)

    # show credential
    cred = cred_private.show_credential([True, True, True, False])
    assert cred.verify_credential(issuer_pk)
    assert cred.get_message() == b"This isn't a test message."
    assert cred.get_attributes() == [13, 'Hello', 'WoRlD', None]

    with pytest.raises(Exception):
        cred_private.show_credential([True, False, True, False])


def test_acl_invalid():
    # generating keys and wrappers
    issuer_priv, issuer_pk = ACLParam().generate_new_key_pair()
    issuer_priv2, issuer_pk2 = ACLParam().generate_new_key_pair()
    attrs = [Bn(13), "Hello", "WoRlD", "Hidden"]

    # verifying against wrong public key
    issuer = ACLIssuer(issuer_priv, issuer_pk)
    user = ACLUser(issuer_pk)
    cred_private = auto_cred(user, issuer, attrs)
    cred = cred_private.show_credential([True, True, True, False])
    assert not cred.verify_credential(issuer_pk2)

    # wrong secret key
    issuer = ACLIssuer(issuer_priv2, issuer_pk)
    user = ACLUser(issuer_pk)
    cred_private = auto_cred(user, issuer, attrs)
    cred = cred_private.show_credential([True, True, True, False])
    assert not cred.verify_credential(issuer_pk)

    # wrong public key for the issuer
    issuer = ACLIssuer(issuer_priv, issuer_pk2)
    user = ACLUser(issuer_pk)
    cred_private = auto_cred(user, issuer, attrs)
    cred = cred_private.show_credential([True, True, True, False])
    assert not cred.verify_credential(issuer_pk)
    assert not cred.verify_credential(issuer_pk2)

    # wrong public key for the user
    issuer = ACLIssuer(issuer_priv, issuer_pk)
    user = ACLUser(issuer_pk2)
    cred_private = auto_cred(user, issuer, attrs)
    cred = cred_private.show_credential([True, True, True, False])
    assert not cred.verify_credential(issuer_pk)
    assert not cred.verify_credential(issuer_pk2)

    # reveal with partial mask
    issuer = ACLIssuer(issuer_priv, issuer_pk)
    user = ACLUser(issuer_pk)
    cred_private = auto_cred(user, issuer, attrs)
    with pytest.raises(Exception):
        cred = cred_private.show_credential([True, True])


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
    com = signer.commit()
    challenge = user.compute_blind_challenge(com, message)
    resp = signer.respond(challenge)
    sig = user.compute_signature(resp)

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


def test_pack_acl():
    issuer_priv, issuer_pk = ACLParam().generate_new_key_pair()
    issuer = ACLIssuer(issuer_priv, issuer_pk)
    user = ACLUser(issuer_pk)
    attrs = [Bn(13), "Hello", "WoRlD", "Hidden"]
    message = "This isn't a test message."

    m0 = user.prove_attr_knowledge(attrs)
    m1 = issuer.commit(m0)
    m2 = user.compute_blind_challenge(m1, message)
    m3 = issuer.respond(m2)
    cred_private = user.compute_credential(m3)
    cred = cred_private.show_credential([True, True, True, False])

    m0p = packb(m0)
    m1p = packb(m1)
    m2p = packb(m2)
    m3p = packb(m3)
    cred_privatep = packb(cred_private)
    credp = packb(cred)

    
    # the original message is representing m0.nizk_proof.response as list while
    # the unpacked version represent it as a tuple
    # assert unpackb(m0p) == m0

    assert unpackb(m1p) == m1
    assert unpackb(m2p) == m2
    assert unpackb(m3p) == m3
    assert unpackb(cred_privatep) == cred_private
    assert unpackb(credp) == cred

    cred = unpackb(credp)
    assert cred.verify_credential(issuer_pk)
    assert cred.get_message() == b"This isn't a test message."
    assert cred.get_attributes() == [13, 'Hello', 'WoRlD', None]


def main():
    pass


if __name__ == '__main__':
    main()
