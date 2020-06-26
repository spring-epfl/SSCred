import cProfile
import pstats

from petlib.bn import Bn

from sscred.acl import *

# To average the differences.
N_REPETITIONS = 1000


def print_title(title):
    "Print a title for a profile output."
    print('')
    print(title)
    print('-' * len(title))


def profile_ACL():
    "profile for ACL."
    pr = cProfile.Profile()
    pr.enable()

    for _ in range(N_REPETITIONS):
        # generating keys and wrappers

        issuer_priv, issuer_pk = ACLParam().generate_new_key_pair()
        issuer = ACLIssuer(issuer_priv, issuer_pk)
        user = ACLUser(issuer_pk)

        # Issuance
        message = "Hello world"
        attributes = [Bn(13), "Hello", "WoRlD", "Hidden"]
        m0 = user.prove_attr_knowledge(attributes)
        m1 = issuer.commit(m0)
        m2 = user.compute_blind_challenge(m1, message)
        m3 = issuer.respond(m2)
        cred_private = user.compute_credential(m3)

        # show credential
        cred = cred_private.show_credential([True, True, True, False])
        assert cred.verify_credential(issuer_pk)

    pr.disable()

    print_title('ACL Profile')
    pr.print_stats()

if __name__ == '__main__':
    profile_ACL()
