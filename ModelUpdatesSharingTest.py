import os
import math
from SubProtocolsStandaloneVersion import setup
from Server import Server
from Client import Client
from Protocols import model_updates_sharing_locally

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
print("test data of client 1:",test_data)

# generate client object 2
test_data = []
for i in range(data_dimension):
    test_data.append(int.from_bytes(os.urandom(num_bytes), 'big') & mask)

client_obj2 = Client(id=2, data=test_data, SS_type="t1", ring_size=ring_size)
print("test data of client 2:",test_data)

# execute model updates sharing 
result = model_updates_sharing_locally(client_objs=(client_obj1, client_obj2), 
                                       server_objs=(server_obj_S1, server_obj_S2, server_obj_S3))

if result == True:
    print("model updates sharing is correct.")
else:
    print("model updates sharing is wrong!")