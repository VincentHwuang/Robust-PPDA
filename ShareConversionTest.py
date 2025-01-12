import os
import math
import numpy as np
from Server import Server
from Client import Client
from SubProtocolsStandaloneVersion import setup, clients_send_shares_locally, semihonest_share_conversion_locally, clients_send_reduced_shares_locally

'''
codes to test the correctness of share conversion from 
boolean sharing to arithmetic sharing over a ring \mathbb{Z}_{2^{\ell}}
'''
# generate server objects
ring_size = 32
mask = pow(2, ring_size) - 1
num_bytes = math.ceil(ring_size / 8)
setup_materials = setup(num_bytes)
server_obj_S1 = Server(id=1, ring_size=ring_size, keys=setup_materials['keys'][0], PRF_counters=setup_materials['PRF_counters'][0])
server_obj_S2 = Server(id=2, ring_size=ring_size, keys=setup_materials['keys'][1], PRF_counters=setup_materials['PRF_counters'][1])
server_obj_S3 = Server(id=3, ring_size=ring_size, keys=setup_materials['keys'][2], PRF_counters=setup_materials['PRF_counters'][2])

data_dimension = 2
# generate client object 1
test_data = []
for i in range(data_dimension):
    test_data.append(int.from_bytes(os.urandom(num_bytes), 'big') & mask)

client_obj1 = Client(id=1, data=test_data, SS_type="t1", ring_size=ring_size)
# execute secret sharing
client_obj1.generate_shares()
print("test data of client 1:",test_data)

# generate client object 2
test_data = []
for i in range(data_dimension):
    test_data.append(int.from_bytes(os.urandom(num_bytes), 'big') & mask)

client_obj2 = Client(id=2, data=test_data, SS_type="t1", ring_size=ring_size)
# execute boolean secret sharing
client_obj2.generate_shares()
print("test data of client 2:",test_data)

# client sends boolean shares to servers
# clients_send_shares_locally(client_objs=(client_obj1, client_obj2), server_objs=(server_obj_S1, server_obj_S2, server_obj_S3))

# communication optimized version 
clients_send_reduced_shares_locally(client_objs=(client_obj1, client_obj2), server_objs=(server_obj_S1, server_obj_S2, server_obj_S3))

# share conversion for dimension 1
converted_shares_S1, \
converted_shares_S2, \
converted_shares_S3 = semihonest_share_conversion_locally(server_objs=(server_obj_S1, server_obj_S2, server_obj_S3),
                                                                                                    client_id='1',
                                                                                                    dimension='1',
                                                                                                    ring_size=ring_size)
print("converted shares of S1:",converted_shares_S1)
print("converted shares of S2:",converted_shares_S2)
print("converted shares of S3:",converted_shares_S3)

if converted_shares_S1[0] == converted_shares_S2[0] and converted_shares_S1[1] == converted_shares_S3[1] and converted_shares_S2[1] == converted_shares_S3[0]:
    print("converted shares are consistent.")
    print("sum:",(converted_shares_S1[0] + converted_shares_S1[1] + converted_shares_S2[1]) & mask)

# share conversion for dimension 1
converted_shares_S1, converted_shares_S2, converted_shares_S3 = semihonest_share_conversion_locally(server_objs=(server_obj_S1, server_obj_S2, server_obj_S3),
                                                                                                    client_id='2',
                                                                                                    dimension='2',
                                                                                                    ring_size=ring_size)
print("converted shares of S1:",converted_shares_S1)
print("converted shares of S2:",converted_shares_S2)
print("converted shares of S3:",converted_shares_S3)

if converted_shares_S1[0] == converted_shares_S2[0] and converted_shares_S1[1] == converted_shares_S3[1] and converted_shares_S2[1] == converted_shares_S3[0]:
    print("converted shares are consistent.")
    print("sum:",(converted_shares_S1[0] + converted_shares_S1[1] + converted_shares_S2[1]) & mask)
