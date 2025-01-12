import os
import math
from typing import Tuple, List, Dict, Union
from Server import Server
from Client import Client

# unified interface to open secrets locally, for simulation 
def open_locally(secret_label : str, 
                      server_objs : Tuple[Server], 
                      client_id : str,
                      data_indices : List[int] = [0]) -> bool:
    if secret_label == "with_indices":
        return safe_open_with_indices_locally(server_objs = server_objs, data_indices = data_indices)
    elif secret_label == "v":
        return safe_open_v_locally(server_objs = server_objs)
    elif secret_label == "rhos_sigmas":
        return open_rhos_sigmas_locally(server_objs = server_objs, client_id=client_id)
    else:
        return False

# open secrets by given data indices, locally, for simulation
def safe_open_with_indices_locally(server_objs : Tuple[Server], data_indices : List[int]) -> bool:
    assert len(server_objs) == 3
    for i in range(len(data_indices)):
        # send shares
        share_S1 = server_objs[0].send_shares_locally(data_indices[i])
        share_S2 = server_objs[1].send_shares_locally(data_indices[i])
        share_S3 = server_objs[2].send_shares_locally(data_indices[i])

        # recover secrets
        server_objs[0].recover_locally(data_indices[i], share_S3)
        server_objs[1].recover_locally(data_indices[i], share_S1)
        server_objs[2].recover_locally(data_indices[i], share_S2)

    # send views of opened values
    view_S1 = server_objs[0].send_view_locally(data_indices)
    view_S2 = server_objs[1].send_view_locally(data_indices)
    view_S3 = server_objs[2].send_view_locally(data_indices)
    # compare views of opened values
    result_S1 = server_objs[0].compare_view_locally(view_S3)
    result_S2 = server_objs[1].compare_view_locally(view_S1)
    result_S3 = server_objs[2].compare_view_locally(view_S2)

    if result_S1 == True and result_S2 == True and result_S3 == True:
        return True
    else:
        return False

# safely open 'v' locally, for simulation 
def safe_open_v_locally(server_objs : Tuple[Server]) -> bool:
    assert len(server_objs) == 3
    # send share 
    v_share_S1 = server_objs[0].send_share_of_v_locally()
    v_share_S2 = server_objs[1].send_share_of_v_locally()
    v_share_S3 = server_objs[2].send_share_of_v_locally()
    # recover 'v'
    server_objs[0].recover_v_locally(v_share_S3)
    server_objs[1].recover_v_locally(v_share_S1)
    server_objs[2].recover_v_locally(v_share_S2)

    # send view of opened 'v'
    view_S1 = server_objs[0].send_view_of_v_locally()
    view_S2 = server_objs[1].send_view_of_v_locally()
    view_S3 = server_objs[2].send_view_of_v_locally()

    # compare views of opened 'v'
    result_S1 = server_objs[0].compare_view_locally(view_S3)
    result_S2 = server_objs[1].compare_view_locally(view_S1)
    result_S3 = server_objs[2].compare_view_locally(view_S2)

    if result_S1 == True and result_S2 == True and result_S3 == True:
        return True
    else:
        return False

# open rho's and sigma's locally, for simulation 
def open_rhos_sigmas_locally(server_objs : Tuple[Server], client_id : str) -> bool:
    assert len(server_objs) == 3
    # send shares
    sent_shares_S1 = server_objs[0].send_rho_sigma_shares_locally(client_id=client_id)
    sent_shares_S2 = server_objs[1].send_rho_sigma_shares_locally(client_id=client_id)
    sent_shares_S3 = server_objs[2].send_rho_sigma_shares_locally(client_id=client_id)
    # recover secrets and compute the view 
    view_S1 = server_objs[0].recover_rhos_sigmas_locally(sent_shares_S3, client_id=client_id)
    view_S2 = server_objs[1].recover_rhos_sigmas_locally(sent_shares_S1, client_id=client_id)
    view_S3 = server_objs[2].recover_rhos_sigmas_locally(sent_shares_S2, client_id=client_id)
    # compute views of opened rhos and sigmas
    result_S1 = server_objs[0].compare_view_locally(view_S3)
    result_S2 = server_objs[0].compare_view_locally(view_S1)
    result_S3 = server_objs[0].compare_view_locally(view_S2)

    if result_S1 == True and result_S2 == True and result_S3 == True:
        return True
    else:
        return False

# check correctness locally, for simulation
def check_correctness_locally(server_objs : Tuple[Server], client_ids : Tuple[str]) -> bool:
    assert len(server_objs) == 3
    # send correctness check shares
    view_S1 = server_objs[0].send_correctness_check_view_locally(client_ids=client_ids)
    view_S2 = server_objs[1].send_correctness_check_view_locally(client_ids=client_ids)
    view_S3 = server_objs[2].send_correctness_check_view_locally(client_ids=client_ids)

    # set correctness check view locally
    server_objs[0].set_correctness_check_view(client_ids=client_ids)
    server_objs[1].set_correctness_check_view(client_ids=client_ids)
    server_objs[2].set_correctness_check_view(client_ids=client_ids)

    result_S1 = server_objs[0].compare_view_locally(view_S3)
    result_S2 = server_objs[1].compare_view_locally(view_S1)
    result_S3 = server_objs[2].compare_view_locally(view_S2)

    if result_S1 == True and result_S2 == True and result_S3 == True:
        return True
    else:
        return False

# share zero locally, for simulation
def share_zero_locally(server_objs : Tuple[Server]) -> bool:
    assert len(server_objs) == 3
    zero_shares = []
    for i in range(3):
        zero_shares.append(server_objs[i].generate_zero_share())
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

# semi-honest secure squared \ell_2-norm computation locally, for simulation 
def compute_l2norm_with_semihonest_security_locally(server_objs : Tuple[Server], client_id : str, ring_size : int) -> Tuple[Tuple[int]]:
    assert len(server_objs) == 3
    # call zero sharing subprotocol to generate alpha, beta and gamma
    share_zero_locally(server_objs)
    # generate (3,3)-sharing of y
    share_of_y_S1 = server_objs[0].generate_33share_of_y(client_id=client_id)
    share_of_y_S2 = server_objs[1].generate_33share_of_y(client_id=client_id)
    share_of_y_S3 = server_objs[2].generate_33share_of_y(client_id=client_id)

    # set t1-sharing of y
    y_share_S1 = server_objs[0].set_t1_sharing_of_y_locally(share_of_y_S3, client_id=client_id)
    y_share_S2 = server_objs[1].set_t1_sharing_of_y_locally(share_of_y_S1, client_id=client_id)
    y_share_S3 = server_objs[2].set_t1_sharing_of_y_locally(share_of_y_S2, client_id=client_id)

    # check if the sum of shares exceed the modulus, if it is, regenerate reduced shares 
    if (y_share_S1[0] + y_share_S1[1] + y_share_S2[1]) >= pow(2,ring_size):
        mask = pow(2, ring_size) - 1
        sum = (y_share_S1[0] + y_share_S1[1] + y_share_S2[1]) & mask
        num_bytes = math.ceil(ring_size / 8)
        y_12 = int.from_bytes(os.urandom(num_bytes), 'big') & mask
        y_13 = int.from_bytes(os.urandom(num_bytes), 'big') & mask
        y_23 = sum - y_12 - y_13
        
        server_objs[0].set_reduced_t1_sharing_of_y_locally((y_12,y_13), client_id=client_id)
        server_objs[1].set_reduced_t1_sharing_of_y_locally((y_12,y_23), client_id=client_id)
        server_objs[2].set_reduced_t1_sharing_of_y_locally((y_23,y_13), client_id=client_id)
    else:
        server_objs[0].set_reduced_t1_sharing_of_y_locally(y_share_S1, client_id=client_id)
        server_objs[1].set_reduced_t1_sharing_of_y_locally(y_share_S2, client_id=client_id)
        server_objs[2].set_reduced_t1_sharing_of_y_locally(y_share_S3, client_id=client_id)
    return (y_share_S1, y_share_S2, y_share_S3)

# semi-honest multiplication subprotocol, locally, for simulation 
def semihonest_multiplication_locally(server_objs : Tuple[Server], operands_id : List[str]) -> Tuple[Tuple[int]]:
    assert len(server_objs) == 3
    # call zero sharing subprotocol to generate alpha, beta and gamma
    share_zero_locally(server_objs)
    # generate (3,3)-sharing of output
    share_of_output_S1 = server_objs[0].generate_33share_of_output(operands_id)
    share_of_output_S2 = server_objs[1].generate_33share_of_output(operands_id)
    share_of_output_S3 = server_objs[2].generate_33share_of_output(operands_id)
    # set t1-sharing i.e., (3,2)-RSS of y
    t1_share_S1 = server_objs[0].set_t1_sharing_of_y_locally(share_of_output_S3)
    t1_share_S2 = server_objs[1].set_t1_sharing_of_y_locally(share_of_output_S1)
    t1_share_S3 = server_objs[2].set_t1_sharing_of_y_locally(share_of_output_S2)

    return (t1_share_S1, t1_share_S2, t1_share_S3)

# check if the opened 'v' is 0 locally, for simulation 
def check_v_locally(server_objs : Tuple[Server]) -> bool:
    assert len(server_objs) == 3
    result_S1 = server_objs[0].check_v()
    result_S2 = server_objs[1].check_v()
    result_S3 = server_objs[2].check_v()

    if result_S1 == True and result_S2 == True and result_S3 == True:
        return True
    else:
        return False
    
# check norm locally, for simulation
def norm_check_locally(server_objs : Tuple[Server], client_id : str) -> bool:
    assert len(server_objs) == 3
    # each server generates a random common non-zero value alpha
    for i in range(3):
        server_objs[i].generate_nonzero_alpha()

    # each server computes [\rho_i]=\alpha[x_i]+[a_i],[\sigma_i]=[x_i]+[a_i], i=1,...,d
    for i in range(3):
        server_objs[i].compute_rho_sigma_shares(client_id=client_id)

    # open all \rho_i,\sigma_i,i=1,...,d
    open_result = open_locally(secret_label = "rhos_sigmas", server_objs = server_objs, client_id=client_id)
    if open_result == False:
        print("failed to open rhos_sigmas")
        return False

    # each server computes [v]=\alpha[y]-\sum_i[c_i]+\sum_i(\sigma_i[a_i]+\rho_i[a_i]-\rho_i\sigma_i)
    for i in range(3):
        server_objs[i].compute_v_share(client_id=client_id)

    # open [v] and compare view of opened 'v'
    open_result = open_locally(secret_label="v", server_objs = server_objs, client_id=client_id)
    if open_result == False:
        print("failed to open v!")
        return False
   
    # check if the opened 'v' is 0
    check_result = check_v_locally(server_objs = server_objs)
    return check_result

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

# set sharings of random squared correlation pairs for simulation 
def set_sharings_of_random_squared_correlation_paris(server_objs : Tuple[Server], 
                                                     shares : Dict[str, List[List[Tuple]]]) -> bool:
    assert len(server_objs) == 3 and len(shares.keys()) == 2
    num_shares = [len(shares[key]) for key in shares.keys()]            
    assert num_shares[0] == num_shares[1]
    data_dimension = num_shares[0]
    for key in shares.keys():
            for i in range(data_dimension):
                for j in range(3):
                    server_objs[j].set_sharings_of_random_squared_correlation_pairs(label = key, shares = shares[key][i][j])

    return True

# offline protocol locally, for simulation 
def offline_protocol_locally(ring_size : int, data_dimension: int, server_objs : Tuple[Server]) -> bool:
    shares_of_random_squared_correlation_pairs = generate_sharings_of_random_squared_correlation_pairs(ring_size, data_dimension)
    set_sharings_of_random_squared_correlation_paris(server_objs, shares_of_random_squared_correlation_pairs)

    return True 

# clients send shares of private inputs to servers locally, for simulation 
def clients_send_shares_locally(client_objs : Tuple[Client], server_objs : Tuple[Server]) -> bool:
    assert len(server_objs) == 3
    num_clients = len(client_objs)
    for i in range(num_clients):
        shares_of_private_input, shares_of_squares = client_objs[i].send_shares_locally()
        server_objs[0].get_boolean_shares_locally(client_id=str(i+1), shares=shares_of_private_input[0])
        server_objs[1].get_boolean_shares_locally(client_id=str(i+1), shares=shares_of_private_input[1])
        server_objs[2].get_boolean_shares_locally(client_id=str(i+1), shares=shares_of_private_input[2])

        # partial_shares_of_private_input = client_objs[i].send_reduced_shares_locally()
        # server_objs[0].get_reduced_boolean_shares_locally(client_id=str(i+1), shares=partial_shares_of_private_input[0])
        # server_objs[1].get_reduced_boolean_shares_locally(client_id=str(i+1), shares=partial_shares_of_private_input[1])
        # server_objs[2].get_reduced_boolean_shares_locally(client_id=str(i+1), shares=partial_shares_of_private_input[2])

    return True

# clients send reduced shares of private inputs to servers locally, for simulation 
def clients_send_reduced_shares_locally(client_objs : Tuple[Client], server_objs : Tuple[Server]) -> bool:
    assert len(server_objs) == 3
    num_clients = len(client_objs)
    for i in range(num_clients):
        shares_of_S1, shares_of_S2, shares_of_S3 = client_objs[i].send_reduced_shares_locally()
        server_objs[0].get_reduced_boolean_shares_locally(client_id=str(i+1), shares=shares_of_S1)
        server_objs[1].get_reduced_boolean_shares_locally(client_id=str(i+1), shares=shares_of_S2)
        server_objs[2].get_reduced_boolean_shares_locally(client_id=str(i+1), shares=shares_of_S3)

# compute arithmetic shares of each bit, locally, for simulation 
def compute_arithmetic_shares_of_bits_locally(server_objs : Tuple[Server], client_id : str, dimension : int) -> bool:
    assert len(server_objs) == 3
    # servers generate random shares of bit shares of specific dimension and client
    shares_returned_by_S1 = server_objs[0].generate_random_shares_of_bits(client_id, dimension)
    shares_returned_by_S2 = server_objs[1].generate_random_shares_of_bits(client_id, dimension)
    shares_returned_by_S3 = server_objs[2].generate_random_shares_of_bits(client_id, dimension)

    # send shares between servers
    # server 1 to server 2
    send_shares_for_share_conversion_locally(from_server_id=1, 
                                             to_server=server_objs[1], 
                                             shares=shares_returned_by_S1['to_S2'], 
                                             client_id=client_id,
                                             dimension=dimension)
    # server 1 to server 3
    send_shares_for_share_conversion_locally(from_server_id=1, 
                                             to_server=server_objs[2], 
                                             shares=shares_returned_by_S1['to_S3'],
                                             client_id=client_id,
                                             dimension=dimension)
    # server 2 to server 1
    send_shares_for_share_conversion_locally(from_server_id=2, 
                                             to_server=server_objs[0], 
                                             shares=shares_returned_by_S2['to_S1'],
                                             client_id=client_id,
                                             dimension=dimension)
    # server 2 to server 3
    send_shares_for_share_conversion_locally(from_server_id=2, 
                                             to_server=server_objs[2], 
                                             shares=shares_returned_by_S2['to_S3'],
                                             client_id=client_id,
                                             dimension=dimension)
    # server 3 to server 1
    send_shares_for_share_conversion_locally(from_server_id=3, 
                                             to_server=server_objs[0], 
                                             shares=shares_returned_by_S3['to_S1'],
                                             client_id=client_id,
                                             dimension=dimension)
    # server 3 to server 2
    send_shares_for_share_conversion_locally(from_server_id=3, 
                                             to_server=server_objs[1], 
                                             shares=shares_returned_by_S3['to_S2'],
                                             client_id=client_id,
                                             dimension=dimension)
    
    return True

# share conversion with semi-honest security locally for simulation 
def semihonest_share_conversion_locally(server_objs : Tuple[Server], client_id : str, dimension : str, ring_size : int) -> Tuple[Tuple[int]]:
    # compute arithmetic shares of each bit
    compute_arithmetic_shares_of_bits_locally(server_objs=server_objs, client_id=client_id, dimension=dimension)
    # compute arithmetic shares of \sigma_i,i=0,...,\ell-1
    compute_arithmetic_shares_of_sigmai_locally(server_objs=server_objs, ring_size=ring_size, client_id=client_id, dimension=dimension)
    # compute arithmetic shares of each bit x_i,i=0,...,\ell-1
    compute_arithmetic_shares_of_xi_locally(server_objs=server_objs, ring_size=ring_size, client_id=client_id, dimension=dimension)
    # compute targeted arithmetic shares of secret 
    x_12_S1, x_13_S1 = server_objs[0].generate_targeted_arithmetic_shares(client_id=client_id, dimension=dimension)
    x_12_S2, x_23_S2 = server_objs[1].generate_targeted_arithmetic_shares(client_id=client_id, dimension=dimension)
    x_23_S3, x_13_S3 = server_objs[2].generate_targeted_arithmetic_shares(client_id=client_id, dimension=dimension)

    return ((x_12_S1, x_13_S1), (x_12_S2, x_23_S2), (x_23_S3, x_13_S3))

# send shares for share conversion between servers locally, for simulation 
def send_shares_for_share_conversion_locally(from_server_id : int, 
                                             to_server : Server, 
                                             shares : List[Tuple[int]],
                                             client_id : str,
                                             dimension : int) -> bool:
    to_server.receive_shares_for_share_conversion_locally(from_server_id=from_server_id, 
                                                          shares=shares,
                                                          client_id=client_id,
                                                          dimension=dimension)
    return True

# servers compute arithmetic shares of \sigma_i= [x_i]_12+[x_i]_{13}-2[x_i]_{12}[x_i]_{13}, locally, for simulation 
def compute_arithmetic_shares_of_sigmai_locally(server_objs : Tuple[Server], 
                                                ring_size : int, 
                                                client_id : str,
                                                dimension : int) -> bool:
    assert len(server_objs) == 3
    mask = pow(2, ring_size) - 1
    # compute shares of xi_12 + xi_13 using local computation
    shares_of_x12_add_x13_S1 = server_objs[0].compute_arithmetic_shares_of_x12_add_x13(client_id=client_id, dimension=dimension)
    shares_of_x12_add_x13_S2 = server_objs[1].compute_arithmetic_shares_of_x12_add_x13(client_id=client_id, dimension=dimension)
    shares_of_x12_add_x13_S3 = server_objs[2].compute_arithmetic_shares_of_x12_add_x13(client_id=client_id, dimension=dimension)
    # compute shares of xi_12 * xi_13 using multiplication subprotocol 
    shares_of_x12_multiply_x13_S1 = []
    shares_of_x12_multiply_x13_S2 = []
    shares_of_x12_multiply_x13_S3 = []
    for i in range(ring_size):
        operands_id = ['x'+str(i)+'12', 'x'+str(i)+'13']
        shares = semihonest_multiplication_locally(server_objs=server_objs, operands_id=operands_id)
        shares_of_x12_multiply_x13_S1.append(shares[0])
        shares_of_x12_multiply_x13_S2.append(shares[1])
        shares_of_x12_multiply_x13_S3.append(shares[2])

    shares_of_sigmai_S1 = []
    shares_of_sigmai_S2 = []
    shares_of_sigmai_S3 = []
    # compute shares of \sigma_i
    for i in range(ring_size):
        sigmai_S1_12 = (shares_of_x12_add_x13_S1[i][0] - 2 * shares_of_x12_multiply_x13_S1[i][0]) & mask
        sigmai_S1_13 = (shares_of_x12_add_x13_S1[i][1] - 2 * shares_of_x12_multiply_x13_S1[i][1]) & mask
        shares_of_sigmai_S1.append((sigmai_S1_12, sigmai_S1_13))

        sigmai_S2_12 = (shares_of_x12_add_x13_S2[i][0] - 2 * shares_of_x12_multiply_x13_S2[i][0]) & mask
        sigmai_S2_23 = (shares_of_x12_add_x13_S2[i][1] - 2 * shares_of_x12_multiply_x13_S2[i][1]) & mask
        shares_of_sigmai_S2.append((sigmai_S2_12, sigmai_S2_23))

        sigmai_S3_23 = (shares_of_x12_add_x13_S3[i][0] - 2 * shares_of_x12_multiply_x13_S3[i][0]) & mask
        sigmai_S3_13 = (shares_of_x12_add_x13_S3[i][1] - 2 * shares_of_x12_multiply_x13_S3[i][1]) & mask
        shares_of_sigmai_S3.append((sigmai_S3_23, sigmai_S3_13))

    # set shares of \sigma_i
    server_objs[0].get_shares_of_sigmai_in_share_conversion(shares_of_sigmai_S1)
    server_objs[1].get_shares_of_sigmai_in_share_conversion(shares_of_sigmai_S2)
    server_objs[2].get_shares_of_sigmai_in_share_conversion(shares_of_sigmai_S3)

    return True

# servers compute targeted converted shares of x_i, locally, for simulation 
def compute_arithmetic_shares_of_xi_locally(server_objs : Tuple[Server], 
                                            ring_size : int, 
                                            client_id : str,
                                            dimension : int) -> bool:
    assert len(server_objs) == 3
    mask = pow(2, ring_size) - 1
    # compute shares of \sigma_i + xi_23 using local computation 
    shares_of_sigmai_add_x23_S1 = server_objs[0].compute_arithmetic_shares_of_sigmai_add_x23(client_id=client_id, dimension=dimension)
    shares_of_sigmai_add_x23_S2 = server_objs[1].compute_arithmetic_shares_of_sigmai_add_x23(client_id=client_id, dimension=dimension)
    shares_of_sigmai_add_x23_S3 = server_objs[2].compute_arithmetic_shares_of_sigmai_add_x23(client_id=client_id, dimension=dimension)
    # compute shares of \sigma_i * xi_23 using multiplication subprotocol 
    shares_of_sigmai_multiply_x23_S1 = []
    shares_of_sigmai_multiply_x23_S2 = []
    shares_of_sigmai_multiply_x23_S3 = []
    for i in range(ring_size):
        operands_id = ['sigma'+str(i), 'x'+str(i)+'23']
        shares = semihonest_multiplication_locally(server_objs=server_objs, operands_id=operands_id)
        shares_of_sigmai_multiply_x23_S1.append(shares[0])
        shares_of_sigmai_multiply_x23_S2.append(shares[1])
        shares_of_sigmai_multiply_x23_S3.append(shares[2])

    shares_of_xi_S1 = []
    shares_of_xi_S2 = []
    shares_of_xi_S3 = []
    # compute shares of x_i
    for i in range(ring_size):
        xi_S1_12 = (shares_of_sigmai_add_x23_S1[i][0] - 2 * shares_of_sigmai_multiply_x23_S1[i][0]) & mask
        xi_S1_13 = (shares_of_sigmai_add_x23_S1[i][1] - 2 * shares_of_sigmai_multiply_x23_S1[i][1]) & mask
        shares_of_xi_S1.append((xi_S1_12, xi_S1_13))

        xi_S2_12 = (shares_of_sigmai_add_x23_S2[i][0] - 2 * shares_of_sigmai_multiply_x23_S2[i][0]) & mask
        xi_S2_23 = (shares_of_sigmai_add_x23_S2[i][1] - 2 * shares_of_sigmai_multiply_x23_S2[i][1]) & mask
        shares_of_xi_S2.append((xi_S2_12, xi_S2_23))

        xi_S3_23 = (shares_of_sigmai_add_x23_S3[i][0] - 2 * shares_of_sigmai_multiply_x23_S3[i][0]) & mask
        xi_S3_13 = (shares_of_sigmai_add_x23_S3[i][1] - 2 * shares_of_sigmai_multiply_x23_S3[i][1]) & mask
        shares_of_xi_S3.append((xi_S3_23, xi_S3_13))

    # set shares of xi
    server_objs[0].get_shares_of_xi_in_share_conversion(shares_of_xi_S1)
    server_objs[1].get_shares_of_xi_in_share_conversion(shares_of_xi_S2)
    server_objs[2].get_shares_of_xi_in_share_conversion(shares_of_xi_S3)

    return True

# two servers S_i,S_j generate boolean shares of a ring element x, locally, for simulation 
def two_servers_generate_boolean_shares(server_objs : Tuple[Server], server_ids : Tuple[str], client_id :str) -> Union[Tuple[Tuple[int,int],bytes], bool]:
    assert len(server_objs) == 2 and len(server_ids) == 2 and server_ids[0] in ('1','2','3') and server_ids[1] in ('1','2','3')
    if server_ids[0] == '1' and server_ids[1] == '2':
        # S_1,S_2 generate boolean shares of x_12, 
        # and send shares and its digest to S_3
        (x_12_23,x_12_13) = server_objs[0].generate_boolean_shares_with_another_server(server_id='2',client_id=client_id)
        digest = server_objs[1].generate_boolean_shares_with_another_server(server_id='1',client_id=client_id)
        return ((x_12_23,x_12_13), digest)

    elif server_ids[0] == '1' and server_ids[1] == '3':
        # S_1,S_3 generate boolean shares of x_13, 
        # and send shares and its digest to S_2
        (x_13_12,x_13_23) = server_objs[0].generate_boolean_shares_with_another_server(server_id='3',client_id=client_id)
        digest = server_objs[1].generate_boolean_shares_with_another_server(server_id='1',client_id=client_id)
        return ((x_13_12,x_13_23),digest)

    elif server_ids[0] == '2' and server_ids[1] == '3':
        # S_2,S_3 generate boolean shares of x_23, 
        # and send shares and its digest to S_1
        (x_23_12,x_23_13) = server_objs[0].generate_boolean_shares_with_another_server(server_id='3',client_id=client_id)
        digest = server_objs[1].generate_boolean_shares_with_another_server(server_id='2',client_id=client_id)
        return ((x_23_12,x_23_13),digest)

    else:
        print("server ids are invalid.")
        return False
    
# distribute shares of l2 norm bound to servers
def distribute_shares_of_l2_norm_bound(server_objs : Tuple[List], shares : Tuple[Tuple[int,int]]) -> bool:
    assert len(server_objs) == 3 and len(shares) == 3
    server_objs[0].receive_shares_of_l2norm_bound(shares[0])
    server_objs[1].receive_shares_of_l2norm_bound(shares[1])
    server_objs[2].receive_shares_of_l2norm_bound(shares[2])
    return True

# check if the norm violates the specified bound 
def check_if_norm_violates_bound(server_objs : Tuple[int], client_id :str) -> bool:
    assert len(server_objs) == 3
    # servers locally compute the difference between norm and the bound 
    for i in range(3):
        server_objs[i].compute_difference_between_norm_and_bound(client_id=client_id)
    # servers open and check the difference
    # S_1 sends d_12 to S_3, S_2 sends d_23 to S_1, S_3 sends d_13 to S_2
    d_12_S1 = server_objs[0].return_share_of_difference(client_id=client_id)
    d_23_S2 = server_objs[1].return_share_of_difference(client_id=client_id)
    d_13_S3 = server_objs[2].return_share_of_difference(client_id=client_id)
    # servers recover the difference
    recovered_d_S1 = server_objs[0].recover_difference(client_id=client_id, receive_share=d_23_S2)
    recovered_d_S2 = server_objs[1].recover_difference(client_id=client_id, receive_share=d_13_S3)
    recovered_d_S3 = server_objs[2].recover_difference(client_id=client_id, receive_share=d_12_S1)
    # check if the recovered difference is consistent and if the norm violates the bound
    check_result_S1 = server_objs[0].check_norm_bound(client_id=client_id, receive_difference = recovered_d_S3)
    check_result_S2 = server_objs[1].check_norm_bound(client_id=client_id, receive_difference = recovered_d_S1)
    check_result_S3 = server_objs[2].check_norm_bound(client_id=client_id, receive_difference = recovered_d_S2)

    if check_result_S1[0] == True and check_result_S2[0] == True and check_result_S3[0] == True:
        print("\033[32mdifference computation check pass.\033[0m")
        if check_result_S1[1] == False and check_result_S2[1] == False and check_result_S3[1] == False:
            print("\033[32mnorm of client",client_id," is valid.\033[0m")
            return True
        else:
            print("\033[31mnorm of client",client_id," is invalid in that it violates the bound!\033[0m")
            return False
    else:
        print("\033[31mdifference computation does not check pass in that the shares are inconsistent!\033[0m")
        return False
    

