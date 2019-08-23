import copy
import pytest

from petlib.bn import Bn

from sscred.commitment import *
from sscred.blind_signature import *
from sscred.blind_pedersen import *
from sscred.acl import *
from sscred.pack import packb, unpackb, add_msgpack_support


def test_pedersen_commit_verification():
	values = [Bn(2651), Bn(1), Bn(98)]
	pparam = CommitParam(hs_size=len(values))
	pcommit, prand = pparam.commit(values)
	assert pcommit.verify(pparam, prand, values)


def test_pedersen_commit_proof():
	values = [Bn(2651), Bn(1), Bn(98)]
	pparam = CommitParam(hs_size=len(values))
	pcommit, prand = pparam.commit(values)
	proof = pcommit.prove_attributes(pparam, prand, values)
	assert pcommit.verify_proof(pparam, proof)


def test_pedersen_commit_invalid_proof():
	values = [Bn(2651), Bn(1), Bn(98)]
	pparam = CommitParam(hs_size=len(values))
	pcommit, prand = pparam.commit(values)
	prand = pparam.q.random()
	assert not pcommit.verify(pparam, prand, values)
	proof = pcommit.prove_attributes(pparam, prand, values)
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
		message = "Hello world"
		sig = auto_sign(signer, user, message)
		assert pk.verify_signature(sig)
		assert message.encode('utf8') == sig.message


def test_abe_signature_verification_corupted():
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
	param.set_blindness_param(param.group.hash_to_point(b"bl_z"),
		param.group.hash_to_point(b"bl_g"))

	# reveal nothing
	bcommit, bpriv = param.blind_commit(values)
	bproof = bcommit.prove_attributes(bpriv)
	assert bcommit.verify_proof(bproof)

	# revealing some values
	bproof2 = bcommit.prove_attributes(bpriv, reveal_mask=[True, False, True, True])
	assert bcommit.verify_proof(bproof2)
	assert bproof2.revealed_values == [Bn(123), None, 'hello', b"world"]


def test_bl_pedersen_without_second_randomizer_valid():
	values = [Bn(123), Bn(456), 'hello', b"world"]
	param = BlindedPedersenParam(hs_size=len(values))
	# remove 'H2' generator and randomness (pure blind pedersen)
	param.set_blindness_param(param.group.hash_to_point(b"bl_z"))
	bcommit, bpriv = param.blind_commit(values)

	bproof = bcommit.prove_attributes(bpriv, reveal_mask=[True, False, True, True])
	assert bcommit.verify_proof(bproof)
	assert bproof.revealed_values == [Bn(123), None, 'hello', b"world"]


def test_bl_pedersen_invalid():
	values = [Bn(123), Bn(456), 'hello', b"world"]
	param = BlindedPedersenParam(hs_size=len(values))
	param.set_blindness_param(param.group.hash_to_point(b"bl_z"),
		param.group.hash_to_point(b"bl_g"))
	bcommit, bpriv = param.blind_commit(values)

	# corrupt rand
	bpriv2 = copy.deepcopy(bpriv)
	bpriv2.rand.value = param.q.random()
	bproof = bcommit.prove_attributes(bpriv2, reveal_mask=[True, False, True, True])
	assert not bcommit.verify_proof(bproof)

	# corrupt rand2
	bpriv3 = copy.deepcopy(bpriv)
	bpriv3.rand_2.value = param.q.random()
	bproof = bcommit.prove_attributes(bpriv3, reveal_mask=[True, False, True, True])
	assert not bcommit.verify_proof(bproof)

	# corrupt blindness
	bpriv4 = copy.deepcopy(bpriv)
	bpriv4.blindness_rand.value = param.q.random()
	bproof = bcommit.prove_attributes(bpriv4, reveal_mask=[True, False, True, True])
	assert not bcommit.verify_proof(bproof)

	# corrupt revealed value
	# This leads to different zksk.statement constants between prover and
	# verifier which result in StatementMismatch exception. verify_proof checks
	# for this statement and convert it to False
	bpriv5 = copy.deepcopy(bpriv)
	bpriv5.values[0].value = param.q.random()
	bproof = bcommit.prove_attributes(bpriv5, reveal_mask=[True, False, True, True])
	assert not bcommit.verify_proof(bproof)

	# corrupt hidden value
	bpriv6 = copy.deepcopy(bpriv)
	bpriv6.values[1].value = param.q.random()
	bproof = bcommit.prove_attributes(bpriv6, reveal_mask=[True, False, True, True])
	assert not bcommit.verify_proof(bproof)


def auto_cred(user, signer, attrs):
	# Interactive signing
	message = "This isn't a test message."
	m0 = user.prove_attr_knowledge(attrs)
	m1 = signer.commit(m0)
	m2 = user.compute_blind_challenge(m1, message)
	m3 = signer.respond(m2)
	return user.compute_credential(m3)


def test_acl_valid():
	# generating keys and wrappers
	signer_priv, signer_pk = ACLParam().generate_new_key_pair()
	signer = ACLSigner(signer_priv, signer_pk)
	user = ACLUser(signer_pk)

	attrs = [Bn(13), "Hello", "WoRlD", "Hidden"]
	cred_private = auto_cred(user, signer, attrs)

	# show credential
	cred = cred_private.show_credential([True, True, True, False])
	assert cred.verify_credential(signer_pk)
	assert cred.get_message() == b"This isn't a test message."
	assert cred.get_attributes() == [13, 'Hello', 'WoRlD', None]

	with pytest.raises(Exception):
		assert cred_private.show_credential([True, False, True, False])


def test_acl_invalid():
	# generating keys and wrappers
	signer_priv, signer_pk = ACLParam().generate_new_key_pair()
	signer_priv2, signer_pk2 = ACLParam().generate_new_key_pair()
	attrs = [Bn(13), "Hello", "WoRlD", "Hidden"]

	# verifying against wrong public key
	signer = ACLSigner(signer_priv, signer_pk)
	user = ACLUser(signer_pk)
	cred_private = auto_cred(user, signer, attrs)
	cred = cred_private.show_credential([True, True, True, False])
	assert not cred.verify_credential(signer_pk2)

	# wrong secret key
	signer = ACLSigner(signer_priv2, signer_pk)
	user = ACLUser(signer_pk)
	cred_private = auto_cred(user, signer, attrs)
	cred = cred_private.show_credential([True, True, True, False])
	assert not cred.verify_credential(signer_pk)

	# wrong public key for the signer
	signer = ACLSigner(signer_priv, signer_pk2)
	user = ACLUser(signer_pk)
	cred_private = auto_cred(user, signer, attrs)
	cred = cred_private.show_credential([True, True, True, False])
	assert not cred.verify_credential(signer_pk)
	assert not cred.verify_credential(signer_pk2)

	# wrong public key for the user
	signer = ACLSigner(signer_priv, signer_pk)
	user = ACLUser(signer_pk2)
	cred_private = auto_cred(user, signer, attrs)
	cred = cred_private.show_credential([True, True, True, False])
	assert not cred.verify_credential(signer_pk)
	assert not cred.verify_credential(signer_pk2)


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


def main():
	pass


if __name__ == '__main__':
	main()
