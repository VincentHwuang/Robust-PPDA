import os
import sys
import math
import time
import random
import logging
import coloredlogs
import socket 
from bitarray import bitarray
from typing import List,Tuple

coloredlogs.install(level='DEBUG')
logging.basicConfig(level=logging.DEBUG,
                    format='%(name)s: %(message)s',
                    )

num_clients = 5
data_dimension = 10
bound_of_each_dimension = pow(2,3)
# data ring size
aggregation_bound = num_clients * bound_of_each_dimension
data_num_bytes = math.ceil(math.log(aggregation_bound+1, 2) / 8)
data_ring_size = data_num_bytes * 8
data_mask = pow(2, data_ring_size) - 1
'''
bound of squared l2 norm \mu, if the upper bound of each dimension is A = pow(2,ring_size)-1, 
then the upper bound of l2 norm is pow(A, 2) * data_dimension 
'''
mu2 = pow(bound_of_each_dimension, 2) * data_dimension
num_bytes = math.ceil(math.log(mu2+1,2) / 8)
ring_size = num_bytes * 8
mask = pow(2, ring_size) - 1

server_addresses = [('localhost', 9123),('localhost', 9124),('localhost', 9125)]

time_share_generation = 0

def generate_shares(data : List[int]) -> List[List]:
    global time_share_generation
    start = time.perf_counter()
    # select three random seeds
    s_0 = int.from_bytes(os.urandom(num_bytes), sys.byteorder)
    s_1 = int.from_bytes(os.urandom(num_bytes), sys.byteorder)
    shares_S1, shares_S2, shares_S3 = [], [], []

    shares_S1.append(s_0)
    shares_S1.append(s_1)
    shares_S2.append(s_0)
    shares_S3.append(s_1)

    for i in range(data_dimension):
        random.seed(s_0)
        s_0 += 1
        x_i_12 = random.randint(0, pow(2, ring_size)-1)
        random.seed(s_1)
        s_1 += 1
        x_i_13 = random.randint(0, pow(2, ring_size)-1)
        # compute x_i_23
        x_i_23 = data[i] ^ x_i_12 ^ x_i_13
        
        # extract partial boolean shares to send to servers
        x_i_23 = bitarray(bin(x_i_23)[2:][::-1])
        assert len(x_i_23) <= ring_size
        if len(x_i_23) < ring_size:
            x_i_23.extend('0' * (ring_size - len(x_i_23)))
        
        shares_S2.append(x_i_23)
        shares_S3.append(x_i_23)
    
    end = time.perf_counter()
    time_share_generation += (end - start)
    return [shares_S1, shares_S2, shares_S3]
    
# generate test data
test_data = []
shares_of_test_data = []
for i in range(num_clients):
    test_data_i = []
    for j in range(data_dimension):
        # data_dimension_j = int.from_bytes(os.urandom(data_num_bytes), sys.byteorder) & mask
        data_dimension_j = 1
        test_data_i.append(data_dimension_j)
    test_data.append(test_data_i)
    # print('test data of client ',i+1,'\n',test_data_i)
    # generate shares
    shares_of_test_data.append(generate_shares(test_data_i))
    # print('client: ',i+1,'shares:\n',shares_of_test_data[i])

print('average running time of share generation per client:',time_share_generation/num_clients,'s')

# generate sharings of the l2 norm bound 
shares_of_l2_norm_bound = {}
mu2_12 = int.from_bytes(os.urandom(num_bytes), sys.byteorder) & mask 
mu2_13 = int.from_bytes(os.urandom(num_bytes), sys.byteorder) & mask 
mu2_23 = (mu2 - mu2_12 - mu2_13) & mask 
shares_of_l2_norm_bound['to_S1'] = (mu2_12,mu2_13)
shares_of_l2_norm_bound['to_S2'] = (mu2_12,mu2_23)
shares_of_l2_norm_bound['to_S3'] = (mu2_23,mu2_13)
# print('shares of l2 norm bould:\nserver 1: ',shares_of_l2_norm_bound['to_S1'],'\nserver 2: ',shares_of_l2_norm_bound['to_S2'],'\nserver 3: ',shares_of_l2_norm_bound['to_S3'])

for i in range(len(server_addresses)):
    for j in range(num_clients):
        logger = logging.getLogger('Client '+str(j+1))

        # connect to the server
        socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.info('connecting to server '+str(i+1))
        while(socket_obj.connect_ex(server_addresses[i])):
            time.sleep(5)

        # send the data 
        request = 'CLIENT-DATAUPLOADING'
        logger.info('sending request: CLIENT-DATAUPLOADING to server '+str(i+1))
        socket_obj.send(request.encode())
        # send id 
        id = str(j+1)
        if len(id) < 4:
            id = '0' * (4 - len(id)) + id
        socket_obj.send(id.encode())

        # receive a response
        response = socket_obj.recv(1024)
        logger.info('receive response from server '+str(i+1)+': %s',response.decode())

        shares_Si = shares_of_test_data[j][i]
        # logger.debug('shares to send to server '+str(i+1)+':\n%s',shares_Si)
        num_shares = len(shares_Si)
        # send number of shares
        socket_obj.send(num_shares.to_bytes(3, sys.byteorder))
        # send ring size 
        socket_obj.send(ring_size.to_bytes(1, sys.byteorder))
        if i == 0: # send shares to server 1
            socket_obj.send(data_dimension.to_bytes(3, sys.byteorder))
            logger.info('send two seeds to server 1...')
            for k in range(num_shares):
                socket_obj.send(shares_Si[k].to_bytes(num_bytes, sys.byteorder))

        else: # send data to server 2 and server 3
            # the first share is the seed 
            logger.info('send the seed and shares to server '+str(i+1)+'...')
            logger.info('send the seed...')
            socket_obj.send(shares_Si[0].to_bytes(num_bytes, sys.byteorder))
            logger.info('send the shares...')
            for k in range(1,data_dimension+1):
                # logger.debug('sent to server: %s, client: %s, dimension: %s, correct share: %s',i+1,j+1,k,shares_Si[k])
                socket_obj.send(shares_Si[k].tobytes())
                
        if j == 0:
            # send shares of l2 norm bound 
            for k in range(2):
                if i == 0:
                    socket_obj.send(shares_of_l2_norm_bound['to_S1'][k].to_bytes(num_bytes, sys.byteorder))
                elif i == 1:
                    socket_obj.send(shares_of_l2_norm_bound['to_S2'][k].to_bytes(num_bytes, sys.byteorder))
                else:
                    socket_obj.send(shares_of_l2_norm_bound['to_S3'][k].to_bytes(num_bytes, sys.byteorder))

        # clean up 
        socket_obj.close()

    