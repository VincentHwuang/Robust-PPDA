import os
import math
from SubProtocolsStandaloneVersion import setup, distribute_shares_of_l2_norm_bound
from Server import Server
from Client import Client
from Utility import compute_l2_norm
from Protocols import model_updates_sharing_locally, \
                    norm_bounding_based_selection_locally

num_clients = 5
data_dimension = 10
# data ring size
data_ring_size = 16
data_num_bytes = math.ceil(data_ring_size / 8)
'''
bound of squared l2 norm \mu, if the upper bound of each dimension is A = pow(2,ring_size)-1, 
then the upper bound of l2 norm is pow(A, 2) * data_dimension 
'''
bound_of_each_dimension = pow(2, data_ring_size) - 1 
mu = pow(bound_of_each_dimension, 2) * data_dimension

print("\033[34msquared norm bound:\033[0m")
print(mu)
ring_size = math.ceil(math.log(mu+1, 2))+1
mask = pow(2, ring_size) - 1
num_bytes = math.ceil(ring_size / 8)
print("\033[34mmodulus:\033[0m",pow(2, ring_size))

# generate and distribute arithmetic shares of the bound
mu_12 = int.from_bytes(os.urandom(num_bytes), 'big') & mask
mu_13 = int.from_bytes(os.urandom(num_bytes), 'big') & mask
mu_23 = (mu - mu_12 - mu_13) 

# generate server objects
setup_materials = setup(num_bytes)
server_obj_S1 = Server(id=1, ring_size=ring_size, keys=setup_materials['keys'][0], PRF_counters=setup_materials['PRF_counters'][0])
server_obj_S2 = Server(id=2, ring_size=ring_size, keys=setup_materials['keys'][1], PRF_counters=setup_materials['PRF_counters'][1])
server_obj_S3 = Server(id=3, ring_size=ring_size, keys=setup_materials['keys'][2], PRF_counters=setup_materials['PRF_counters'][2])
server_objs = (server_obj_S1, server_obj_S2, server_obj_S3)

distribute_shares_of_l2_norm_bound(server_objs=server_objs, shares=((mu_12,mu_13),(mu_12,mu_23),(mu_23,mu_13)))

# generate client objects
client_objs = []
test_data = []
l2_norms = []
for i in range(num_clients):
    test_data_i = []
    for j in range(data_dimension):
        test_data_i.append(pow(2,data_ring_size)-2)
        # test_data_i.append(int.from_bytes(os.urandom(data_num_bytes), 'big'))
    l2_norms.append(compute_l2_norm(data=test_data_i))
    test_data.append(test_data_i)
    # print("\033[34mdata of client",i+1,":\033[0m")
    # print(test_data_i)
    client_obj = Client(id=i+1, data=test_data_i, SS_type="t1", ring_size=ring_size)
    client_objs.append(client_obj)

# execute model updates sharing 
result = model_updates_sharing_locally(client_objs=client_objs, 
                                       server_objs=server_objs)

if result == True:
    print("\033[32mmodel updates sharing is correct.\033[0m")
else:
    print("\033[31mmodel updates sharing is wrong!\033[0m")

# norm-bounding based selection 
data_recovered, l2_norms_recovered = norm_bounding_based_selection_locally(server_objs=server_objs,
                                      num_clients=num_clients,
                                      dimension=data_dimension,
                                      ring_size=ring_size)
if data_recovered == test_data:
    print("\033[32mshare conversion is correct.\033[0m")
else:
    print("\033[31mshare conversion is wrong!\033[0m")

print("\033[34mcorrect l2 norm:",l2_norms,"\033[0m")
if l2_norms_recovered == l2_norms:
    print("\033[32ml2-norm computation is correct.\033[0m")
else:
    print("\033[31ml2-norm computation is wrong!\033[0m")
    print("l2_norms_recovered:",l2_norms_recovered)
    print("l2_norms:",l2_norms)