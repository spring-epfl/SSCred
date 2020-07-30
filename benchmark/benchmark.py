#!/usr/bin/env python3
"Benchmark generation for SSCred ACL and Abe's blind signature submodules."

import gc
import json
import random
import string
import time

from petlib.ec import EcGroup
from petlib.bn import Bn
from sscred.acl import (
    ACLParam,
    ACLIssuer,
    ACLUser
)

from sscred.blind_signature import (
    AbeParam,
    AbeSigner,
    AbeUser
)

from sscred.pack import packb
from sscred.config import DEFAULT_GROUP_ID


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
    "Contains the benchmark data for the Abe's blind signature."

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
        "Run an issuance and store the execution time of the methods executed."
        size_printed = False
        random.seed(42)

        for _ in range(self.n_repetitions):
            protocol_communication = 0      # in Bytes
            signature_size = 0              # in Bytes

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
            protocol_communication += len(packb(com))
            self.t_abe_signer_commit.append(t)

            message = ''.join([random.choice(string.printable) for _ in range(100)])

            challenge, t = perf_measure_call(user.compute_blind_challenge, com, message)
            protocol_communication += len(packb(challenge))
            self.t_user_compute_blind_challenge.append(t)

            resp, t = perf_measure_call(signer.respond, challenge)
            protocol_communication += len(packb(resp))
            self.t_signer_respond.append(t)

            sig, t = perf_measure_call(user.compute_signature, resp)
            # The signature stores the message. This size is dependent on the user's input.
            signature_size = len(packb(sig)) - len(message)
            self.t_user_compute_signature.append(t)

            _, t = perf_measure_call(signer_pub.verify_signature, sig)
            self.t_signer_pub_verify_signature.append(t)
            
            if not size_printed:
                print(f"Abe's signature => size: {signature_size}, communication cost: {protocol_communication}")
                size_printed = True

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
        self.t_acl_issuer_init = list()
        self.t_acl_user_init = list()
        self.t_prove_attr_knowledge = list()
        self.t_issuer_commit = list()
        self.t_user_compute_blind_challenge = list()
        self.t_issuer_respond = list()
        self.t_user_compute_credential = list()
        self.t_cred_private_show_credential = list()
        self.t_cred_verify_credential = list()


    def run(self):
        "Run an issuance and store the execution time of the methods executed."
        size_printed = False
        random.seed(42)

        for _ in range(self.n_repetitions):
            protocol_communication = 0      # in Bytes
            credential_size = 0             # in Bytes
            
            acl_param, t = perf_measure_call(ACLParam)
            self.t_acl_param_init.append(t)

            keys, t = perf_measure_call(acl_param.generate_new_key_pair)
            self.t_generate_new_key_pair.append(t)

            issuer_priv, issuer_pub = keys

            issuer, t = perf_measure_call(ACLIssuer, issuer_priv, issuer_pub)
            self.t_acl_issuer_init.append(t)

            user, t = perf_measure_call(ACLUser, issuer_pub)
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
            protocol_communication += len(packb(m0))
            self.t_prove_attr_knowledge.append(t)

            m1, t = perf_measure_call(issuer.commit, m0)
            protocol_communication += len(packb(m1))
            self.t_issuer_commit.append(t)

            m2, t = perf_measure_call(user.compute_blind_challenge, m1, message)
            protocol_communication += len(packb(m2))
            self.t_user_compute_blind_challenge.append(t)

            m3, t = perf_measure_call(issuer.respond, m2)
            protocol_communication += len(packb(m3))
            self.t_issuer_respond.append(t)

            cred_private, t = perf_measure_call(user.compute_credential, m3)
            self.t_user_compute_credential.append(t)

            cred, t = perf_measure_call(cred_private.show_credential, [True, True, True, False])
            # The credential stores the raw message and attributes. This size is dependent on the user's input. 
            credential_size = len(packb(cred)) - len(message) - len(packb(cred_private.bpriv.raw_values))
            self.t_cred_private_show_credential.append(t)

            _, t = perf_measure_call(cred.verify_credential, issuer_pub)
            self.t_cred_verify_credential.append(t)

            if not size_printed:
                print(f"ACL => priv: {len(packb(cred_private))}, credential size (showing the credential): {credential_size}, communication cost: {protocol_communication}")
                size_printed = True


    def save(self, filename='acl-benchmark.json'):
        "Save the collected data in json format in a file which name is given in argument."

        file_struct = {}
        file_struct['acl_param_init'] = self.t_acl_param_init
        file_struct['generate_new_key_pair'] = self.t_generate_new_key_pair
        file_struct['acl_issuer_init'] = self.t_acl_issuer_init
        file_struct['acl_user_init'] = self.t_acl_user_init
        file_struct['prove_attr_knowledge'] = self.t_prove_attr_knowledge
        file_struct['issuer_commit'] = self.t_issuer_commit
        file_struct['user_compute_blind_challenge'] = self.t_user_compute_blind_challenge
        file_struct['issuer_respond'] = self.t_issuer_respond
        file_struct['user_compute_credential'] = self.t_user_compute_credential
        file_struct['cred_private_show_credential'] = self.t_cred_private_show_credential
        file_struct['cred_verify_credential'] = self.t_cred_verify_credential

        file_content = json.dumps(file_struct)

        with open(filename, 'w') as fd:
            fd.write(file_content)


if __name__ == '__main__':
    Benchmarks = [ACLBenchmark, AbeBenchmark]
    print(f"Benchmarking with curve {EcGroup.list_curves()[DEFAULT_GROUP_ID]}.")

    for Benchmark in Benchmarks:
        benchmark = Benchmark(n_repetitions=1000)
        benchmark.run()

        benchmark.save()

