# SSCred

A python library to facilitate anonymous authentication. SSCred provides the following primitives:

* Anonymous credential light (ACL)<sup>[1](#cn1)</sup>
* Abe's Blind signature<sup>[2](#cn2)</sup>
* Blinded Pedersen commitment

## Requirement
SSCred depends on the `petlib` and `zksk`  libraries. Before installing the library make sure that  `libssl-dev`, `python-dev`, and `libffi-dev` packages are installed on your machine. You can use following commands on Ubuntu/Debian to install them.

```
sudo apt-get install python-dev
sudo apt-get install libssl-dev
sudo apt-get install libffi-dev
```

Note: Only blinded Pederson commitment and ACL depend on `zksk` and you can use the blind signature without relying on `zksk`.

## Installing
You can use `pip` to install the library.

```
pip install sscred
```

You can use `pytest` to test the installation

```
python -m pytest
```

### Development
If you are interested in contributing to this library, you can clone the code and
install the library in the development mode.

```
git clone https://github.com/spring-epfl/SSCred
cd SSCred
python3 -m venv venv
source venv/bin/activate
pip install -e .
python -m pytest
```

##  Usage
### Anonymous credential light
Provides an one-time-use anonymous credential based on ACL<sup>[1](#cn1)</sup>. The user decides on a list of attributes and a message and engages in an interactive protocol with the issuer. At the end of the protocol, the user computes a credential which is verifiable using the issuer's public key. During this process, the issuer does not learn any information about the attributes or the message.
At a later time, users can show the credential to a verifier to authorize their attributes and the message. This credential is publicly verifiable and anyone who knows the issuer public key can check it. This credential is not linked to the identity of the user. However, using a credential more than once is detectable and the verifier can link interactions with the same credential. In other words, if the user uses the credential more than once, then the credential becomes a pseudo-identity for the user. As a safeguard, the library raises an exception if the user tries to use a credential more than once.

Attributes can be either `int`, `petlib.Bn`, `str`, or `bytes`. The library hashes attributes for internal use but keeps a copy of raw attribute values as private variables. The user can embed a public key in attributes to be able to sign with the credential after receiving it.

  How to use:
```python
>>> # generating keys and wrappers 
>>> issuer_priv, issuer_pk = ACLParam().generate_new_key_pair() 
>>> issuer = ACLIssuer(issuer_priv, issuer_pk) 
>>> user = ACLUser(issuer_pk) 
>>> message = "Hello world"

>>> # Issuance
>>> attributes = [Bn(13), "Hello", "WoRlD", "Hidden"]
>>> attr_proof = user.prove_attr_knowledge(attributes)
>>> com = issuer.commit(attr_proof)
>>> challenge = user.compute_blind_challenge(com, message)
>>> resp = issuer.respond(challenge)
>>> cred_private = user.compute_credential(resp)

>>> # show credential
>>> # Reveal attributes 0, 1, and 2.
>>> cred = cred_private.show_credential([True, True, True, False])
>>> assert cred.verify_credential(issuer_pk)
>>> print(cred.get_message())
b'Hello world'
>>> print(cred.get_attributes())
[13, 'Hello', 'WoRlD', None]
```

### Abe's blind signature
The user decides on a message and engages in an interactive protocol with the signer to compute a signature on the message. This protocol prevents the signer from learning the content of the message. The signature is verifiable by anyone who knows the signer's public key. No one, including the signer, can determine the user's identity when he reveals his signature. This blind signature is similar to an ACL credential with an empty attribute list. This signature is based on Abe's blind signature<sup>[2](#cn2)</sup>. 

  How to use:
```python
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
```

### Blinded Pedersen Commitment
This scheme allows a party to prove the knowledge of a commitment without revealing any information about underlying values or the commitment itself. This primitive is mainly intended as a building block for more complicated primitives rather than direct use. This commitment only accepts values of type `int`, `petlib.Bn`, `str`, or `bytes`.

  How to use:
```python
>>> values = [Bn(123), Bn(456), 'hello', b"world"]
>>> param = BlindedPedersenParam(hs_size=len(values))

>>> # reveal nothing
>>> bcommit, bpriv = param.blind_commit(values)
>>> bproof = bcommit.prove_values(bpriv)
>>> assert bcommit.verify_proof(param, bproof)

>>> # revealing some values
>>> bproof = bcommit.prove_values(bpriv, reveal_mask=[True, False, True, True])
>>> assert bcommit.verify_proof(param, bproof)
>>> print(bproof.revealed_values)
[123, None, 'hello', b'world']  
```

## Performance
We used the `benchmark.py` to evaluate the performance. This scripts runs operations of ACL and Abe's signature 1000 times and records the cost. `benchmarkStats.py` is a script that compiles statistics based on the measurements of `benchmark.py`. 

Curve P-224 and P-256 provide 112-bit and 128-bit security respectively. Curve P-256 is heavily optimized for performance. That is why it has better performance despite higher security.  

All measurements are done on a desktop equipped with Intel(R) Core(TM) i7-9700 CPU @ 3.00GHz and 16GiB of RAM running Debian 10.

### Abe's signature
The size of the message and raw values is not included in the credential as it depends on the user input.
The communication cost shows the transfer cost of running the protocol, and the signature size shows the size of the resulting signature.

| Curve | Key gen (ms) | Signer (ms) | User  (ms) | Verification (ms) | Signature size (B) | Communication (B) |
|-------|:------------:|:-----------:|:----------:|:-----------------:|:------------------:|:-----------------:|
| P-224 |         0.84 |        1.13 |       1.63 |              0.68 |                324 |               367 |
| P-256 |         0.13 |        0.32 |       0.62 |              0.4  |                360 |               413 | 

### ACL
We evaluated ACL credential with 4 attributes; we reveal  3 of these attributes in the showing credential process. 

The communication cost shows the transfer cost of the issuance protocol, and the credential size is the transfer cost of showing the credential. The size of the message and raw values are not included in the credential size as they depend on the user's input. The communication cost of showing the credential is higher than issuance because of large NIZK proofs. 

| Curve | Key gen (ms) | Issuer (ms) | User  (ms) | Showing cred(ms)| Verification (ms) | Credential size (B) | Communication (B) |
|-------|:------------:|:-----------:|:----------:|:---------------:|:-----------------:|:-------------------:|:-----------------:|
| P-224 |         4.96 |        0.80 |       2.02 |            1.92 |              2.52 |                1160 |               772 |
| P-256 |         0.36 |        0.48 |       0.95 |            1.32 |              1.65 |                1284 |               864 |


## Reference
<a id="cn1">1</a>: Baldimtsi, F., & Lysyanskaya, A. (2013). Anonymous credentials light, 1087–1098. https://doi.org/10.1145/2508859.2516687

<a id="cn2">2</a>: Abe, M. A Secure Three-move Blind Signature Scheme for Polynomially Many Signatures.
