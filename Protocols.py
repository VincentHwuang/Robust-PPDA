import SubProtocolsStandaloneVersion as SubProt
from Client import Client
from Server import Server
from typing import List, Tuple
from Utility import check_share_consistency
from SubProtocolsStandaloneVersion import clients_send_reduced_shares_locally, \
                         check_correctness_locally, \
                         norm_check_locally, \
                         semihonest_share_conversion_locally, \
                         compute_l2norm_with_semihonest_security_locally, \
                         generate_sharings_of_random_squared_correlation_pairs, \
                         two_servers_generate_boolean_shares, \
                         check_if_norm_violates_bound

# model updates sharing via network communication 
def model_updates_sharing(client_objs : Tuple[Client], server_objs : Tuple[Server]) -> bool:
    return True

# model updates sharing, locally, for simulation 
def model_updates_sharing_locally(client_objs : Tuple[Client], server_objs : Tuple[Server]) -> bool:
    assert len(server_objs) == 3
    num_clients = len(client_objs)
    client_ids = [str(i+1) for i in range(num_clients)]
    for i in range(num_clients):
        # execute boolean secret sharing 
        client_objs[i].generate_shares()

    # clients send boolean shares to servers with communication optimized version
    clients_send_reduced_shares_locally(client_objs=client_objs, server_objs=server_objs)

    # batch-check the correctness of received shares
    check_result = check_correctness_locally(server_objs=server_objs, client_ids=client_ids)

    return check_result

# norm-bounding based selection via network communication 
def norm_bounding_based_selection(server_objs : Tuple[Server], num_clients : int, dimension : int) -> bool:
    return True

# norm-bounding based selection locally for simulation 
def norm_bounding_based_selection_locally(server_objs : Tuple[Server], num_clients : int, 
                                          dimension : int, ring_size : int) -> Tuple[List[List[int]],List[int]]:
    assert len(server_objs) == 3
    mask = pow(2, ring_size) - 1
    data_recovered = []
    # execute share conversion 
    for i in range(num_clients):
        secrets_of_client_i = []
        for j in range(dimension):
            shares_S1, \
            shares_S2, \
            shares_S3 = semihonest_share_conversion_locally(server_objs=server_objs,
                                                            client_id=str(i+1),
                                                            dimension=str(j+1),
                                                            ring_size=ring_size)
            assert check_share_consistency(shares_S1=shares_S1,
                                           shares_S2=shares_S2,
                                           shares_S3=shares_S3)
            sum = (shares_S1[0] + shares_S1[1] + shares_S2[1]) & mask
            secrets_of_client_i.append(sum)
        data_recovered.append(secrets_of_client_i)

    # generate shares of random square correlation pairs 
    shares_of_random_square_pairs = generate_sharings_of_random_squared_correlation_pairs(ring_size=ring_size,
                                                                                          data_dimension=dimension)
    shares_of_a = shares_of_random_square_pairs['a']
    shares_of_c = shares_of_random_square_pairs['c']
    # set shares 
    for i in range(dimension):
        server_objs[0].set_shares_of_random_squared_correlation_pairs(label='a',shares=shares_of_a[i][0])
        server_objs[0].set_shares_of_random_squared_correlation_pairs(label='c',shares=shares_of_c[i][0])
        server_objs[1].set_shares_of_random_squared_correlation_pairs(label='a',shares=shares_of_a[i][1])
        server_objs[1].set_shares_of_random_squared_correlation_pairs(label='c',shares=shares_of_c[i][1])
        server_objs[2].set_shares_of_random_squared_correlation_pairs(label='a',shares=shares_of_a[i][2])
        server_objs[2].set_shares_of_random_squared_correlation_pairs(label='c',shares=shares_of_c[i][2])
    # compute l2-norm and check the correctness of computation 
    l2_norms_recovered = []
    for i in range(num_clients):
        shares_S1, shares_S2, shares_S3 = compute_l2norm_with_semihonest_security_locally(server_objs=server_objs, 
                                                                                          client_id=str(i+1),
                                                                                          ring_size=ring_size)
        assert check_share_consistency(shares_S1=shares_S1, shares_S2=shares_S2, shares_S3=shares_S3)
        sum = (shares_S1[0] + shares_S1[1] + shares_S2[1]) & mask
        l2_norms_recovered.append(sum)
        # execute correctness check of norm computation
        norm_check_result = norm_check_locally(server_objs=server_objs, client_id=str(i+1))
        if norm_check_result == True:
            print("\033[32mnorm computation check pass.\033[0m")
        else:
            print("\033[31mnorm computation check does not pass!\033[0m")

        # check if the norm violates the specified bound 
        check_if_norm_violates_bound(server_objs=server_objs, client_id=str(i+1))

        # # servers generate boolean shares of l2 norm shares
        # # S_1,S_2 generate shares of x_12
        # result_S1_S2 = two_servers_generate_boolean_shares(server_objs=(server_objs[0],server_objs[1]),
        #                                                     server_ids=('1','2'),
        #                                                     client_id=str(i+1))
        # if result_S1_S2 is not False:
        #     shares_S1_S2, digest_S1_S2 = result_S1_S2[0], result_S1_S2[1]
        # else:
        #     print("S_1,S_2 fail to generate boolean shares of l2 norm shares.")

        # # S_1,S_3 generate shares of x_13
        # result_S1_S3 = two_servers_generate_boolean_shares(server_objs=(server_objs[0],server_objs[2]),
        #                                                     server_ids=('1','3'),
        #                                                     client_id=str(i+1))
        # if result_S1_S3 is not False:
        #     shares_S1_S3, digest_S1_S3 = result_S1_S3[0], result_S1_S3[1]
        # else:
        #     print("S_1,S_3 fail to generate boolean shares of l2 norm shares.")

        # # S_2,S_3 generate shares of x_23
        # result_S2_S3 = two_servers_generate_boolean_shares(server_objs=(server_objs[1],server_objs[2]),
        #                                                     server_ids=('2','3'),
        #                                                     client_id=str(i+1))
        # if result_S2_S3 is not False:
        #     shares_S2_S3, digest_S2_S3 = result_S2_S3[0], result_S2_S3[1]
        # else:
        #     print("S_2,S_3 fail to generate boolean shares of l2 norm shares.")

        # # servers receive boolean shares of l2 norm shares
        # # S_1 receives (x_23_12,x_23_13)
        # result_S1 = server_objs[0].receive_shares_of_l2norm_shares(shares=shares_S2_S3, 
        #                                                            digest=digest_S2_S3,
        #                                                            client_id=str(i+1))
        # # S_2 receives (x_13_12,x_13_23)
        # result_S2 = server_objs[1].receive_shares_of_l2norm_shares(shares=shares_S1_S3,
        #                                                            digest=digest_S1_S3,
        #                                                            client_id=str(i+1))
        # # S_3 receives (x_12_23,x_12_13)
        # result_S3 = server_objs[2].receive_shares_of_l2norm_shares(shares=shares_S1_S2,
        #                                                            digest=digest_S1_S2,
        #                                                            client_id=str(i+1))
        # assert result_S1 == True and result_S2 == True and result_S3 == True

    return (data_recovered, l2_norms_recovered)