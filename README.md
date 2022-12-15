> Disclaimer: this is a fork of https://github.com/spring-epfl/SSCred/ where we removed `zksk` dependency and therefore the use of commitment and ACL. Only Abe's blind signature.

# SSCred

A python library to facilitate anonymous authentication. SSCred provides the following primitives:

- Anonymous credential light (ACL)<sup>[1](#cn1)</sup>
- Abe's Blind signature<sup>[2](#cn2)</sup>

## Requirement

SSCred depends on the `petlib` libraries. Before installing the library make sure that `libssl-dev`, `python-dev`, and `libffi-dev` packages are installed on your machine. You can use following commands on Ubuntu/Debian to install them.

```
sudo apt-get install python-dev
sudo apt-get install libssl-dev
sudo apt-get install libffi-dev
```

## Installing

### With poetry

Install system dependencies once and for all::

```
make install_dependencies
```

To develop, `install Poetry <https://python-poetry.org/docs/#installation>`\_ then just run::

```
make install
make tests
```

To run the server:

```
    make run
```

### With pip

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

## Usage

### Abe's blind signature

The user decides on a message and engages in an interactive protocol with the signer to compute a signature on the message. This protocol prevents the signer from learning the content of the message. The signature is verifiable by anyone who knows the signer's public key. No one, including the signer, can determine the user's identity when he reveals his signature. This blind signature is similar to an ACL credential with an empty attribute list. This signature is based on Abe's blind signature<sup>[3](#cn3)</sup>.

_Note_: The ROS attack <sup>[2](#cn2)</sup> does **not** impact the security of Abe's signature.

How to use:

```python
>>> # generating keys and wrappers
>>> priv, pk = AbeParam().generate_new_key_pair()
>>> signer = AbeSigner(priv, pk)
>>> user = AbeUser(pk)
>>> message = "Hello world"

>>> # Interactive signing
>>> com, signer_state = signer.commit()
>>> challenge, user_state = user.compute_blind_challenge(com, message)
>>> resp = signer.respond(challenge, signer_state)
>>> sig = user.compute_signature(resp, user_state)

>>> # Verifying the signature
>>> assert pk.verify_signature(sig)
>>> print(sig.message)
b'Hello world'
```

## Performance

We used the `benchmark.py` to evaluate the performance. This scripts runs operations of ACL and Abe's signature 1000 times and records the cost. `benchmarkStats.py` is a script that compiles statistics based on the measurements of `benchmark.py`.

Curve P-224 and P-256 provide 112-bit and 128-bit security respectively. Curve P-256 is heavily optimized for performance. That is why it has better performance despite higher security.

All measurements are done on a desktop equipped with Intel(R) Core(TM) i7-9700 CPU @ 3.00GHz and 16GiB of RAM running Debian 10.

### Abe's signature

The size of the message and raw values is not included in the credential as it depends on the user input.
The communication cost shows the transfer cost of running the protocol, and the signature size shows the size of the resulting signature.

| Curve | Key gen (ms) | Signer (ms) | User (ms) | Verification (ms) | Signature size (B) | Communication (B) |
| ----- | :----------: | :---------: | :-------: | :---------------: | :----------------: | :---------------: |
| P-224 |     0.84     |    1.13     |   1.63    |       0.68        |        324         |        367        |
| P-256 |     0.13     |    0.32     |   0.62    |        0.4        |        360         |        413        |

## Reference

<a id="cn2">2</a>: Benhamouda F, Lepoint T, Loss J, Orrù M, Raykova M. On the (in) security of ROS. EuroCrypt 2021

<a id="cn3">3</a>: Abe, M. A Secure Three-move Blind Signature Scheme for Polynomially Many Signatures.
