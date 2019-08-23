
# SSCred

A python library to facilitate anonymous authentication. SSCred providers following primitives:

* Anonymous credential light<sup>[1](#cn1)</sup>
* Abe's Blind signature<sup>[2](#cn2)</sup>
* Blinded Pedersen commitment

## Install
SSCred is dependent on `petlib` library. Before installing `petlib` you need to ensure that `libssl-dev`, `python-dev`, and `libffi-dev` are installed. You can use following commands on Ubuntu/Debian to install them.

```
sudo apt-get install python-dev
sudo apt-get install libssl-dev
sudo apt-get install libffi-dev
```

**Warning**: SSCred is dependent on the `zksk` library. Currently, this library is private, and you need to install it manually.

Afterward, you can install the package with `pip`.

```
pip install -e
```

Test your installation with

```
pytest
```

##  Usage
### ACL
Provides an one-time use anonymous credential based on ACL<sup>[1](#cn1)</sup>. The user determines a list of attributes and a message and engages in an interactive protocol with the signer. The signer cannot observe the content of attributes or the message. At the end of the protocol, the user receives a credential with signer's signature. 
This credential is verifiable with signer's public key and no one, including the signer, can link it to the user's identity. However, the user cannot use this credential more than once without linking credential uses. In other words, if the user uses the credential more than once, then the credential becomes a pseudo-identity for the user. The library raises an exception if the user tries to use a credential more than once.
The user can embed a public key in attributes to be able to sign with the credential after receiving it.

  How to use:
```python
>>> # generating keys and wrappers
>>> signer_priv, signer_pk = ACLParam().generate_new_key_pair()
>>> signer = ACLSigner(signer_priv, signer_pk)
>>> user = ACLUser(signer_pk)
>>> message = "Hello world"

>>> # Interactive signing
>>> attributes = ["Male", 25, "Researcher", "secret"]
>>> attr_proof = user.prove_attr_knowledge(attributes)
>>> com = signer.commit(attr_proof)
>>> challenge = user.compute_blind_challenge(com, message)
>>> resp = signer.respond(challenge)
>>> cred_private = user.compute_credential(resp)

>>> # show credential
>>> cred = cred_private.show_credential([True, True, True, False])
>>> assert cred.verify_credential(signer_pk)
>>> print(cred.get_message())
b'Hello world'
>>> print(cred.get_attributes())
['Male', 25, 'Researcher', None]
```

### Blind signature
The user decides on a message and engages in an interactive protocol with the signer to receive signer's signature on the message. This protocol prevents the signer from learning the content of the message. The signature is verifiable by anyone who knows signer's public key. When the user decides to reveal the signature, no one, including the signer, can determine the user's identity. This signature is based on Abe's blind signature<sup>[2](#cn2)</sup>.

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
Allows a party to prove the knowledge of a commitment without revealing any information about underlying values or the commitment itself. This primitive is mainly intended as a building block for more complicated primitives rather than direct use. 

  How to use:
```python
>>> values = [Bn(123), Bn(456), 'hello', b"world"]
>>> param = BlindedPedersenParam(hs_size=len(values))
>>> blindness_z_generator = param.group.hash_to_point(b"bl_z")
>>> param.set_blindness_param(blindness_z_generator)
>>> # revealing some values
>>> bproof2 = bcommit.prove_attributes(bpriv, reveal_mask=[True, False, True, False])
>>> assert bcommit.verify_proof(bproof2)
>>> print(bproof2.revealed_values)
[123, None, 'hello', None]
>>> # verifying commit parameters
>>> assert (bcommit.param.verify_parameters(Z=blindness_z_generator))    
```


## Reference
<a id="cn1">1</a>: Baldimtsi, F., & Lysyanskaya, A. (2013). Anonymous credentials light, 1087–1098. https://doi.org/10.1145/2508859.2516687
<a id="cn2">2</a>: Abe, M. A Secure Three-move Blind Signature Scheme for Polynomially Many Signatures.
