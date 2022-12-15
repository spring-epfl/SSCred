from petlib.bn import Bn

from sscred.blind_signature import *
from sscred.pack import *


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
    blind_signature_example()
    pack_example()


if __name__ == "__main__":
    main()
