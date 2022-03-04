from petlib.bn import Bn

from sscred.commitment import *
from sscred.blind_pedersen import *
from sscred.blind_signature import *
from sscred.acl import *
from sscred.pack import *


def pederson_commitment_example():
    values = [Bn(2651), Bn(1), Bn(98)]
    pparam = PedersenParameters(hs_size=len(values))
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
    com, com_params = signer.commit()
    challenge, challenge_params = user.compute_blind_challenge(com, message)
    resp = signer.respond(challenge, com_params)
    sig = user.compute_signature(resp, challenge_params)

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
    com, com_params = issuer.commit(attr_proof)
    challenge, challenge_params = user.compute_blind_challenge(com, message)
    resp = issuer.respond(challenge, com_params)
    cred_private = user.compute_credential(resp, challenge_params)

    # show credential
    cred = cred_private.show_credential([True, True, True, False])
    assert cred.verify_credential(issuer_pk)
    print(cred.message())
    print(cred.attributes())


def pack_example():
    priv, pk = AbeParam().generate_new_key_pair()
    signer = AbeSigner(priv, pk)
    user = AbeUser(pk)
    message = "Hello world"

    com, com_params = signer.commit()
    challenge, challenge_params = user.compute_blind_challenge(com, message)
    resp = signer.respond(challenge, com_params)
    sig = user.compute_signature(resp, challenge_params)

    m1 = packb(com)
    m2 = packb(challenge)
    m3 = packb(resp)
    m4 = packb(sig)
    m5 = packb(priv)
    m6 = packb(pk)
    m7 = packb(com_params)
    m8 = packb(challenge_params)

    assert unpackb(m1) == com
    assert unpackb(m2) == challenge
    assert unpackb(m3) == resp
    assert unpackb(m4) == sig
    assert unpackb(m5) == priv
    assert unpackb(m6) == pk
    assert unpackb(m7) == com_params
    assert unpackb(m8) == challenge_params


def main():
    pederson_commitment_example()
    blinded_pederson_commitment_example()
    blind_signature_example()
    acl_example()
    pack_example()


if __name__ == "__main__":
    main()
