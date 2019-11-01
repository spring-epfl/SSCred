#!/usr/bin/env python3
"Benchmark generation for SSCred ACL submodule."

import gc
import json
import random
import string
import time

from petlib.bn import Bn
from sscred.acl import (
    ACLParam,
    ACLSigner,
    ACLUser
)

from sscred.blind_signature import (
    AbeParam,
    AbeSigner,
    AbeUser
)


def perf_measure_call(fn, *args, **kwargs):
    "Measure the execution time of a function."

    # Ensures the garbage collector is disabled for the benchmark.
    gc_is_enabled = gc.isenabled()
    if gc_is_enabled:
        gc.disable()

    t_begin = time.process_time()

    # Call the function with its arguments
    ret = fn(*args, **kwargs)

    t_end = time.process_time()

    # Collect the garbage manually.
    gc.collect()

    # Re-enable the garbage collector if necessary.
    if gc_is_enabled:
        gc.enable()

    return ret, t_end - t_begin


class AbeBenchmark:
    "Contains the benchmark data for the ACL module."

    def __init__(self, n_repetitions=1000):
        self.n_repetitions = n_repetitions

        self.t_abe_param_init = list()
        self.t_generate_new_key_pair = list()
        self.t_abe_signer_init = list()
        self.t_abe_user_init = list()
        self.t_abe_signer_commit = list()
        self.t_user_compute_blind_challenge = list()
        self.t_signer_respond = list()
        self.t_user_compute_signature = list()
        self.t_signer_pub_verify_signature = list()


    def run(self):
        "Run a complete encryption and store the execution time of the methods executed."

        random.seed(42)

        for _ in range(self.n_repetitions):
            abe_param, t = perf_measure_call(AbeParam)
            self.t_abe_param_init.append(t)

            keys, t = perf_measure_call(abe_param.generate_new_key_pair)
            self.t_generate_new_key_pair.append(t)

            signer_priv, signer_pub = keys

            signer, t = perf_measure_call(AbeSigner, signer_priv, signer_pub)
            self.t_abe_signer_init.append(t)

            user, t = perf_measure_call(AbeUser, signer_pub)
            self.t_abe_user_init.append(t)

            com, t = perf_measure_call(signer.commit)
            self.t_abe_signer_commit.append(t)

            message = ''.join([random.choice(string.printable) for _ in range(100)])

            challenge, t = perf_measure_call(user.compute_blind_challenge, com, message)
            self.t_user_compute_blind_challenge.append(t)

            resp, t = perf_measure_call(signer.respond, challenge)
            self.t_signer_respond.append(t)

            sig, t = perf_measure_call(user.compute_signature, resp)
            self.t_user_compute_signature.append(t)

            _, t = perf_measure_call(signer_pub.verify_signature, sig)
            self.t_signer_pub_verify_signature.append(t)


    def save(self, filename='abe-benchmark.json'):
        "Save the collected data in json format in a file which name is given in argument."

        file_struct = {}
        file_struct['abe_param_init'] = self.t_abe_param_init
        file_struct['generate_new_key_pair'] = self.t_generate_new_key_pair
        file_struct['abe_signer_init'] = self.t_abe_signer_init
        file_struct['abe_user_init'] = self.t_abe_user_init
        file_struct['abe_signer_commit'] = self.t_abe_signer_commit
        file_struct['user_compute_blind_challenge'] = self.t_user_compute_blind_challenge
        file_struct['signer_respond'] = self.t_signer_respond
        file_struct['user_compute_signature'] = self.t_user_compute_signature
        file_struct['signer_pub_verify_signature'] = self.t_signer_pub_verify_signature

        file_content = json.dumps(file_struct)

        with open(filename, 'w') as fd:
            fd.write(file_content)


class ACLBenchmark:
    "Contains the benchmark data for the ACL module."

    def __init__(self, n_repetitions=1000):
        self.n_repetitions = n_repetitions

        self.t_acl_param_init = list()
        self.t_generate_new_key_pair = list()
        self.t_acl_signer_init = list()
        self.t_acl_user_init = list()
        self.t_prove_attr_knowledge = list()
        self.t_signer_commit = list()
        self.t_user_compute_blind_challenge = list()
        self.t_signer_respond = list()
        self.t_user_compute_credential = list()
        self.t_cred_private_show_credential = list()
        self.t_cred_verify_credential = list()


    def run(self):
        "Run a complete encryption and store the execution time of the methods executed."

        random.seed(42)

        for _ in range(self.n_repetitions):
            acl_param, t = perf_measure_call(ACLParam)
            self.t_acl_param_init.append(t)

            keys, t = perf_measure_call(acl_param.generate_new_key_pair)
            self.t_generate_new_key_pair.append(t)

            signer_priv, signer_pub = keys

            signer, t = perf_measure_call(ACLSigner, signer_priv, signer_pub)
            self.t_acl_signer_init.append(t)

            user, t = perf_measure_call(ACLUser, signer_pub)
            self.t_acl_user_init.append(t)

            rnd_attr_num = Bn(random.randint(0, 2**32 - 1))
            rnd_attr_s = [
                ''.join([
                    random.choice(string.printable) for _ in range(10)
                ]) for _ in range(3)
            ]

            attrs = [rnd_attr_num, *rnd_attr_s]
            message = ''.join([random.choice(string.printable) for _ in range(64)])

            m0, t = perf_measure_call(user.prove_attr_knowledge, attrs)
            self.t_prove_attr_knowledge.append(t)

            m1, t = perf_measure_call(signer.commit, m0)
            self.t_signer_commit.append(t)

            m2, t = perf_measure_call(user.compute_blind_challenge, m1, message)
            self.t_user_compute_blind_challenge.append(t)

            m3, t = perf_measure_call(signer.respond, m2)
            self.t_signer_respond.append(t)

            cred_private, t = perf_measure_call(user.compute_credential, m3)
            self.t_user_compute_credential.append(t)

            cred, t = perf_measure_call(cred_private.show_credential, [True, True, True, False])
            self.t_cred_private_show_credential.append(t)

            _, t = perf_measure_call(cred.verify_credential, signer_pub)
            self.t_cred_verify_credential.append(t)


    def save(self, filename='acl-benchmark.json'):
        "Save the collected data in json format in a file which name is given in argument."

        file_struct = {}
        file_struct['acl_param_init'] = self.t_acl_param_init
        file_struct['generate_new_key_pair'] = self.t_generate_new_key_pair
        file_struct['acl_signer_init'] = self.t_acl_signer_init
        file_struct['acl_user_init'] = self.t_acl_user_init
        file_struct['prove_attr_knowledge'] = self.t_prove_attr_knowledge
        file_struct['signer_commit'] = self.t_signer_commit
        file_struct['user_compute_blind_challenge'] = self.t_user_compute_blind_challenge
        file_struct['signer_respond'] = self.t_signer_respond
        file_struct['user_compute_credential'] = self.t_user_compute_credential
        file_struct['cred_private_show_credential'] = self.t_cred_private_show_credential
        file_struct['cred_verify_credential'] = self.t_cred_verify_credential

        file_content = json.dumps(file_struct)

        with open(filename, 'w') as fd:
            fd.write(file_content)


if __name__ == '__main__':
    Benchmark = AbeBenchmark

    if Benchmark:
        benchmark = Benchmark()
        gc.disable()
        benchmark.run()
        gc.enable()

        benchmark.save()

