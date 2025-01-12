import os
import sys
import math
import time
import random
import logging
import coloredlogs
import socket 
from typing import List,Tuple

coloredlogs.install(level='DEBUG')
logging.basicConfig(level=logging.DEBUG,
                    format='%(name)s: %(message)s',
                    )

num_clients = 5
data_dimension = 60
bound_of_each_dimension = 5000
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

# # extract partial boolean shares
def extract_partial_boolean_shares(x_23 : int) -> Tuple[List[int]]:
    shares = ''
    for i in range(ring_size):
        x_23_i = x_23 & 1
        x_23 >>= 1
        shares = shares + str(x_23_i)
    
    return shares

def generate_shares(data : List[int]) -> List[List]:
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
        partial_shares = extract_partial_boolean_shares(x_i_23)
        shares_S2.append(partial_shares)
        shares_S3.append(partial_shares)

    return [shares_S1, shares_S2, shares_S3]
    
# generate test data
test_data = []
shares_of_test_data = []
for i in range(num_clients):
    test_data_i = []
    for j in range(data_dimension):
        # data_dimension_j = int.from_bytes(os.urandom(data_num_bytes), sys.byteorder) & mask
        data_dimension_j = 4321
        test_data_i.append(data_dimension_j)
    test_data.append(test_data_i)
    # print('test data of client ',i+1,'\n',test_data_i)
    # generate shares
    shares_of_test_data.append(generate_shares(test_data_i))

# generate sharings of multiple beaver multiplication triples
shares_of_ais = []
shares_of_cis = []
for i in range(num_clients):
    ais = {'to_S1':[],'to_S2':[],'to_S3':[]}
    cis = {'to_S1':[],'to_S2':[],'to_S3':[]}
    for j in range(data_dimension):
        a_i = int.from_bytes(os.urandom(num_bytes), sys.byteorder) & mask 
        c_i = pow(a_i, 2) & mask 

        ai_12 = int.from_bytes(os.urandom(num_bytes), sys.byteorder) & mask 
        ai_13 = int.from_bytes(os.urandom(num_bytes), sys.byteorder) & mask 
        ai_23 = (a_i - ai_12 - ai_13) & mask 

        ci_12 = int.from_bytes(os.urandom(num_bytes), sys.byteorder) & mask 
        ci_13 = int.from_bytes(os.urandom(num_bytes), sys.byteorder) & mask 
        ci_23 = (c_i - ci_12 - ci_13) & mask 

        ais['to_S1'].append((ai_12,ai_13))
        ais['to_S2'].append((ai_12,ai_23))
        ais['to_S3'].append((ai_23,ai_13))
        cis['to_S1'].append((ci_12,ci_13))
        cis['to_S2'].append((ci_12,ci_23))
        cis['to_S3'].append((ci_23,ci_13))

    shares_of_ais.append(ais)
    shares_of_cis.append(cis)

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
            # send length of each share 
            length_of_seed = (shares_Si[0].bit_length() + 7) // 8
            logger.info('send length of each seed...')
            socket_obj.send(length_of_seed.to_bytes(4, sys.byteorder))
            logger.info('start to upload seeds...')
            for k in range(num_shares):
                socket_obj.send(shares_Si[k].to_bytes(num_bytes, sys.byteorder))

        else: # send data to server 2 and server 3
            # the first share is the seed 
            logger.info('send the seed and shares to server '+str(i+1)+'...')
            length = (shares_Si[0].bit_length() + 7) // 8
            logger.info('send length of the seed...')
            socket_obj.send(length.to_bytes(4, sys.byteorder))
            logger.info('send the seed...')
            socket_obj.send(shares_Si[0].to_bytes(length, sys.byteorder))
            logger.info('send the shares...')
            length = len(shares_Si[1])
            logger.info('send the length of each share...')            
            socket_obj.send(length.to_bytes(4, sys.byteorder))
            for k in range(1,data_dimension+1):
                socket_obj.send(shares_Si[k].encode())
        
        for k in range(data_dimension):
            if i == 0: # send shares of beaver multiplication triples to server 1
                socket_obj.send(shares_of_ais[j]['to_S1'][k][0].to_bytes(num_bytes, sys.byteorder))
                socket_obj.send(shares_of_ais[j]['to_S1'][k][1].to_bytes(num_bytes, sys.byteorder))
                socket_obj.send(shares_of_cis[j]['to_S1'][k][0].to_bytes(num_bytes, sys.byteorder))
                socket_obj.send(shares_of_cis[j]['to_S1'][k][1].to_bytes(num_bytes, sys.byteorder))

            elif i == 1: # send shares of beaver multiplication triples to server 2 
                socket_obj.send(shares_of_ais[j]['to_S2'][k][0].to_bytes(num_bytes, sys.byteorder))
                socket_obj.send(shares_of_ais[j]['to_S2'][k][1].to_bytes(num_bytes, sys.byteorder))
                socket_obj.send(shares_of_cis[j]['to_S2'][k][0].to_bytes(num_bytes, sys.byteorder))
                socket_obj.send(shares_of_cis[j]['to_S2'][k][1].to_bytes(num_bytes, sys.byteorder))

            else: # send shares of beaver multiplication triples to server 3
                socket_obj.send(shares_of_ais[j]['to_S3'][k][0].to_bytes(num_bytes, sys.byteorder))
                socket_obj.send(shares_of_ais[j]['to_S3'][k][1].to_bytes(num_bytes, sys.byteorder))
                socket_obj.send(shares_of_cis[j]['to_S3'][k][0].to_bytes(num_bytes, sys.byteorder))
                socket_obj.send(shares_of_cis[j]['to_S3'][k][1].to_bytes(num_bytes, sys.byteorder))
        
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

    