from sscred.commitment import *
from sscred.blind_pedersen import *
from sscred.blind_signature import *
from sscred.acl import *
from sscred.pack import *


def pederson_commitment_example():
    values = [Bn(2651), Bn(1), Bn(98)]
    pparam = CommitParam(hs_size=len(values))
    pcommit, prand = pparam.commit(values)

    # reveal the opening
    valid = pcommit.verify(pparam, prand, values)
    assert valid

    # Prove the knowledge of opening with a nzkp
    proof = pcommit.prove_knowledge(pparam, prand, values)
    valid = pcommit.verify_proof(pparam, proof)
    print(valid)


def blinded_pederson_commitment_example():
    values = [Bn(123), Bn(456), "hello", b"world"]
    param = BlindedPedersenParam(hs_size=len(values))

    # reveal nothing
    bcommit, bpriv = param.blind_commit(values)
    bproof = bcommit.prove_values(bpriv)
    assert bcommit.verify_proof(param, bproof)

    # revealing some values
    bproof2 = bcommit.prove_values(bpriv, reveal_mask=[True, False, True, True])
    assert bcommit.verify_proof(param, bproof)
    print(bproof2.revealed_values)


def blind_signature_example():
    # generating keys and wrappers
    priv, pk = AbeParam().generate_new_key_pair()
    signer = AbeSigner(priv, pk)
    user = AbeUser(pk)
    message = "Hello world"

    # Interactive signing
    com = signer.commit()
    challenge = user.compute_blind_challenge(com, message)
    resp = signer.respond(challenge)
    sig = user.compute_signature(resp)

    # Verifying the signature
    assert pk.verify_signature(sig)
    print(sig.message)


def acl_example():
    # generating keys and wrappers
    issuer_priv, issuer_pk = ACLParam().generate_new_key_pair()
    issuer = ACLIssuer(issuer_priv, issuer_pk)
    user = ACLUser(issuer_pk)
    message = "Hello world"

    # Issuance
    attributes = [Bn(13), "Hello", "WoRlD", "Hidden"]
    attr_proof = user.prove_attr_knowledge(attributes)
    com = issuer.commit(attr_proof)
    challenge = user.compute_blind_challenge(com, message)
    resp = issuer.respond(challenge)
    cred_private = user.compute_credential(resp)

    # show credential
    cred = cred_private.show_credential([True, True, True, False])
    assert cred.verify_credential(issuer_pk)
    print(cred.get_message())
    print(cred.get_attributes())


def pack_example():
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


def main():
    pederson_commitment_example()
    blinded_pederson_commitment_example()
    blind_signature_example()
    acl_example()
    pack_example()


if __name__ == "__main__":
    main()
