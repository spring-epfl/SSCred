import cProfile

from petlib.bn import Bn

from sscred.acl import *


def bench_ACL():
	# generating keys and wrappers
	signer_priv, signer_pk = ACLParam().generate_new_key_pair()
	signer = ACLSigner(signer_priv, signer_pk)

	for _ in range(100):
		user = ACLUser(signer_pk)
		attrs = [Bn(13), "Hello", "WoRlD", "Hidden"]
		message = "This isn't a test message."

		m0 = user.prove_attr_knowledge(attrs)
		m1 = signer.commit(m0)
		m2 = user.compute_blind_challenge(m1, message)
		m3 = signer.respond(m2)
		cred_private = user.compute_credential(m3)

		# show credential
		cred = cred_private.show_credential([True, True, True, False])
		assert cred.verify_credential(signer_pk)


def main():
	cProfile.run('bench_ACL()')


if __name__ == '__main__':
	main()
