import os
import math
from Server import Server
from SubProtocolsStandaloneVersion import setup, semihonest_multiplication_locally

# codes to test the correctness of the semihonest multiplication subprotocol
ring_size = 32
mask = pow(2, ring_size) - 1
num_bytes = math.ceil(ring_size / 8)
setup_materials = setup(num_bytes)
server_obj_S1 = Server(id=1, ring_size=ring_size, keys=setup_materials['keys'][0], PRF_counters=setup_materials['PRF_counters'][0])
server_obj_S2 = Server(id=2, ring_size=ring_size, keys=setup_materials['keys'][1], PRF_counters=setup_materials['PRF_counters'][1])
server_obj_S3 = Server(id=3, ring_size=ring_size, keys=setup_materials['keys'][2], PRF_counters=setup_materials['PRF_counters'][2])

x = int.from_bytes(os.urandom(num_bytes), 'big') & mask
x_12 = int.from_bytes(os.urandom(num_bytes), 'big') & mask
x_13 = int.from_bytes(os.urandom(num_bytes), 'big') & mask
x_23 = (x - x_12 - x_13) & mask

y = int.from_bytes(os.urandom(num_bytes), 'big') & mask
y_12 = int.from_bytes(os.urandom(num_bytes), 'big') & mask
y_13 = int.from_bytes(os.urandom(num_bytes), 'big') & mask
y_23 = (y - y_12 - y_13) & mask

print("x:", x, "y:", y)
print("x * y:", ((x * y) & mask))

server_obj_S1.get_arithmetic_shares_locally("x", (x_12, x_13))
server_obj_S2.get_arithmetic_shares_locally("x", (x_12, x_23))
server_obj_S3.get_arithmetic_shares_locally("x", (x_23, x_13))

server_obj_S1.get_arithmetic_shares_locally("y", (y_12, y_13))
server_obj_S2.get_arithmetic_shares_locally("y", (y_12, y_23))
server_obj_S3.get_arithmetic_shares_locally("y", (y_23, y_13))

share_S1, share_S2, share_S3 = semihonest_multiplication_locally((server_obj_S1, server_obj_S2, server_obj_S3), operands_id=['x','y'])
if share_S1[0] == share_S2[0] and share_S1[1] == share_S3[1] and share_S2[1] == share_S3[0]:
    print("shares are consistent.")
    print("y_12+y_13_y23=",((share_S1[0] + share_S1[1] + share_S2[1]) & mask))
else:
    print("shares are inconsistent.")

