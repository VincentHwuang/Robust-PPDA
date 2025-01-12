import os
import math
from typing import Tuple, List, Dict
from Server import Server
from Client import Client

# unified interface to open secrets via network communication 
def open(secret_label : str, server_objs : Tuple[Server], data_indices : List[int] = [0]) -> bool:
    return True

# open secrets by given data indices via network communication
def safe_open_with_indices(server_objs : Tuple[Server], data_indices : List[int]) -> bool:
    return True

# safely open 'v' via network communication 
def safe_open_v(server_objs : Tuple[Server]) -> bool:
    return True

# open rho's and sigma's via network communication 
def open_rhos_sigmas(server_objs : Tuple[Server]) -> bool:
    return True

# check correctness via network communication 
def check_correctness(server_objs : Tuple[Server], data_indices : List[int]) -> bool:
    return True

# share zero via network communication
def share_zero(server_objs : Tuple[Server]) -> bool:
    return True

# generate random common keys and PRF counters, simulation of a SMPC protocol
def setup(num_bytes : int) -> Dict[str, List[Tuple]]:
    setup_materials = {'keys':[], 'PRF_counters':[]}
    k12 = int.from_bytes(os.urandom(num_bytes), 'big')
    k13 = int.from_bytes(os.urandom(num_bytes), 'big')
    k23 = int.from_bytes(os.urandom(num_bytes), 'big')
    kS  = int.from_bytes(os.urandom(num_bytes), 'big')

    ctr12 = int.from_bytes(os.urandom(num_bytes), 'big')
    ctr13 = int.from_bytes(os.urandom(num_bytes), 'big')
    ctr23 = int.from_bytes(os.urandom(num_bytes), 'big')
    ctrS  = int.from_bytes(os.urandom(num_bytes), 'big')

    keys_S1 = (k12, k13, kS)
    setup_materials['keys'].append(keys_S1)
    keys_S2 = (k12, k23, kS)
    setup_materials['keys'].append(keys_S2)
    keys_S3 = (k13, k23, kS)
    setup_materials['keys'].append(keys_S3)

    ctrs_S1 = (ctr12, ctr13, ctrS)
    setup_materials['PRF_counters'].append(ctrs_S1)
    ctrs_S2 = (ctr12, ctr23, ctrS)
    setup_materials['PRF_counters'].append(ctrs_S2)
    ctrs_S3 = (ctr13, ctr23, ctrS)
    setup_materials['PRF_counters'].append(ctrs_S3)

    return setup_materials

# semi-honest secure squared \ell_2-norm computation via network communication 
def compute_l2norm_with_semihonest_security(server_objs : Tuple[Server]) -> int:
    return 0

# semi-honest multiplication subprotocol via network communication 
def semihonest_multiplication(server_objs : Tuple[Server]) -> bool:
    return True

# check if the opened 'v' is 0, via network communication 
def check_v(server_objs : Tuple[Server]) -> bool:
    return True

# check norm via network communication 
def norm_check(server_objs : Tuple[Server]) -> bool:
    return True
    
# generate sharings of random squared correlation pairs for simulation 
def generate_sharings_of_random_squared_correlation_pairs(ring_size : int, 
                                                          data_dimension : int) -> Dict[str, List[List[Tuple]]]:
    results = {'a':[], 'c': []}
    mask = pow(2, ring_size) - 1
    num_bytes = math.ceil(ring_size / 8)
    for i in range(data_dimension):
        # generate random shares of 'a_i'
        a_i_12 = int.from_bytes(os.urandom(num_bytes), 'big') & mask
        a_i_13 = int.from_bytes(os.urandom(num_bytes), 'big') & mask
        a_i_23 = int.from_bytes(os.urandom(num_bytes), 'big') & mask
        # compute 'a_i'
        a_i = (a_i_12 + a_i_13 + a_i_23) & mask
        results['a'].append([(a_i_12, a_i_13),(a_i_12, a_i_23),(a_i_23, a_i_13)])
        # compute 'c_i=a_i*a_i'
        c_i = pow(a_i, 2) & mask
        # generate random shares of 'c_i'
        c_i_12 = int.from_bytes(os.urandom(num_bytes), 'big') & mask
        c_i_13 = int.from_bytes(os.urandom(num_bytes), 'big') & mask
        c_i_23 = (c_i - c_i_12 - c_i_13) & mask 
        results['c'].append([(c_i_12, c_i_13),(c_i_12, c_i_23),(c_i_23, c_i_13)])

    return results

# offline protocol via network communication 
def offline_protocol(server_objs : Tuple[Server]) -> bool:
    return True

# clients send shares of private inputs to servers via network communication 
def clients_send_shares(client_objs : Tuple[Client], server_objs : Tuple[Server]) -> bool:
    return True

# compute arithmetic shares of each bit via network communication 
def compute_arithmetic_shares_of_bits(server_objs : Tuple[Server]) -> bool:
    return True

# share conversion with semi-honest security via network communication 
def semihonest_share_conversion(server_objs : Tuple[Server], client_id : str, dimension : int, ring_size : int) -> bool:
    return True

# send shares for share conversion between servers via network communication 
def send_shares_for_share_conversion(from_server_id : int, to_server : Server, shares : List[Tuple[int]]) -> bool:
    return True


# servers compute arithmetic shares of \sigma_i= [x_i]_12+[x_i]_{13}-2[x_i]_{12}[x_i]_{13}, via network communication 
def compute_arithmetic_shares_of_sigmai(server_objs : Tuple[Server]) -> bool:
    return True

# servers compute targeted converted shares of x_i, via network communication 
def compute_arithmetic_shares_of_xi(server_objs : Tuple[Server], ring_size : int) -> bool:
    return True



    

