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
        signer_priv, signer_pub = ACLParam().generate_new_key_pair()
        signer = ACLSigner(signer_priv, signer_pub)

        user = ACLUser(signer_pub)
        attrs = [Bn(13), "Hello", "WoRlD", "Hidden"]
        message = "This isn't a test message."

        m0 = user.prove_attr_knowledge(attrs)
        m1 = signer.commit(m0)
        m2 = user.compute_blind_challenge(m1, message)
        m3 = signer.respond(m2)
        cred_private = user.compute_credential(m3)

        # show credential
        cred = cred_private.show_credential([True, True, True, False])
        cred.verify_credential(signer_pub)

    pr.disable()

    print_title('ACL Profile')
    pr.print_stats()

if __name__ == '__main__':
    profile_ACL()
