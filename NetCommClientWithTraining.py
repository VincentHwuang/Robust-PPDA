import os
import sys
import math
import time
import copy 
import torch 
import random
import logging
import coloredlogs
import socket 
import numpy as np
from torch import nn 
from Model import LeNet
from typing import List,Tuple
from pandas import DataFrame
from FLTrainTest import LocalUpdateLeNet, FedAvg, quantize, flatten_model_update
from LoadData import load_FMNIST_data, dataset_iid

coloredlogs.install(level='DEBUG')
logging.basicConfig(level=logging.DEBUG,
                    format='%(name)s: %(message)s',
                    )

SEED = 1234
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)
torch.cuda.manual_seed(SEED)
if torch.cuda.is_available():
    torch.backends.cudnn.deterministic = True
    print(torch.cuda.get_device_name(0))    

program = "FLLeNetFMNIST"
print(f"---------{program}----------")   # this is to identify the program in the slurm outputs files

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

net_glob = LeNet()

# parameters
batch_size = 256
num_clients = 5
epoches = 1
lr = 0.01
data_dimension = 61706
quantization_precision = 10000
data_ring_size = 16
data_num_bytes = math.ceil(data_ring_size / 8)
'''
bound of squared l2 norm \mu, if the upper bound of each dimension is A = pow(2,ring_size)-1, 
then the upper bound of l2 norm is pow(A, 2) * data_dimension 
'''
bound_of_each_dimension = 5000
mu2 = pow(bound_of_each_dimension, 2) * data_dimension
ring_size_unrounded = math.ceil(math.log(mu2+1, 2))+1
num_bytes = math.ceil(ring_size_unrounded / 8)
ring_size = num_bytes * 8
mask = pow(2, ring_size) - 1

server_addresses = [('localhost', 9123),('localhost', 9124),('localhost', 9125)]

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

# load data
train_dataset, test_dataset = load_FMNIST_data()

# distribute data for users
dict_users_train_dataset = dataset_iid(train_dataset, num_clients)
dict_users_test_dataset = dataset_iid(test_dataset, num_clients)

if torch.cuda.device_count() > 1:
    print("we use", torch.cuda.device_count(), "GPUs")
    net_glob = nn.DataParallel(net_glob) # to use multiple GPUs

net_glob.to(device)
print(net_glob)

# set model to training mode
net_glob.train(True)
# copy parameters
w_glob = net_glob.state_dict()

loss_train_all = []
loss_test_all = []
acc_train_all = []
acc_test_all = []

loggers = [logging.getLogger('Client '+str(i+1)) for i in range(num_clients)]

socket_objs = []
w_local, loss_train_local, loss_test_local,\
acc_train_local, acc_test_local = [], [], [], [], []

# extract partial boolean shares
def extract_partial_boolean_shares(x_23 : int) -> Tuple[List[int]]:
    shares_of_S2, shares_of_S3 = [], []
    for i in range(ring_size):
        x_23_i = x_23 & 1
        x_23 >>= 1
        shares_of_S2.append(x_23_i)
        shares_of_S3.append(x_23_i)
    
    return (shares_of_S2, shares_of_S3)

def generate_shares(data):
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
        partial_shares_of_S2, partial_shares_of_S3 = extract_partial_boolean_shares(x_i_23)
        shares_S2.append(partial_shares_of_S2)
        shares_S3.append(partial_shares_of_S3)

    return [shares_S1, shares_S2, shares_S3]

torch.set_default_dtype(torch.float32)

for epoch in range(epoches):
    for i in range(num_clients):
        # clients handshake with the servers in the first round
        if epoch == 0:
            socket_objs = []
            for j in range(3):
                socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                # connect to the server
                loggers[i].info('connecting to server '+str(j+1))
                while(socket_obj.connect_ex(server_addresses[j])):
                    time.sleep(5)
                socket_objs.append(socket_obj)
                # send the data 
                request = 'CLIENT-DATAUPLOADING'
                loggers[i].info('sending request: CLIENT-DATAUPLOADING to server '+str(j+1))
                socket_obj.send(request.encode())
                # send id 
                id = str(i+1)
                if len(id) < 4:
                    id = '0' * (4 - len(id)) + id
                socket_obj.send(id.encode())

                # receive a response
                response = socket_obj.recv(1024)
                loggers[i].info('receive response from server '+str(j+1)+': %s',response.decode())
        
            # start the 1st-round training 
            local = LocalUpdateLeNet(i, lr, device, train_dataset, 
                                    test_dataset,
                                    idxs_train = dict_users_train_dataset[i], 
                                    idxs_test = dict_users_test_dataset[i])
            # train
            w, loss_train, acc_train = local.train(net = copy.deepcopy(net_glob).to(device))
            w_local.append(copy.deepcopy(w))
            loss_train_local.append(copy.deepcopy(loss_train))
            acc_train_local.append(copy.deepcopy(acc_train))

            # test
            loss_test, acc_test = local.evaluate(net = copy.deepcopy(net_glob).to(device))
            loss_test_local.append(copy.deepcopy(loss_test))
            acc_test_local.append(copy.deepcopy(acc_test))

            # flatten the model update 
            flattened_w = flatten_model_update(w)
            loggers[i].debug('flattened_w[0:100]:\n%s',flattened_w[0:100])

            # quantization 
            quantized_flattened_w = quantize(flattened_w, quantization_precision)
            loggers[i].debug('quantized_flattened_w[0:100]:\n%s',quantized_flattened_w[0:100])

            # generate secret shares 
            shares = generate_shares(quantized_flattened_w)

            # send shares 
            for j in range(3):
                num_shares = len(shares[j])
                # send number of shares
                socket_objs[j].send(num_shares.to_bytes(3, sys.byteorder))
                # send ring size 
                socket_objs[j].send(ring_size.to_bytes(1, sys.byteorder))
                if j == 0: # send shares to server 1 
                    socket_objs[j].send(data_dimension.to_bytes(3, sys.byteorder))
                    loggers[i].info('send two seeds to server 1...')
                    # send length of each share 
                    length_of_seed = (shares[j][0].bit_length() + 7) // 8
                    loggers[i].info('send length of each seed...')
                    socket_objs[j].send(length_of_seed.to_bytes(4, sys.byteorder))
                    loggers[i].info('start to upload seeds...')
                    for k in range(num_shares):
                        socket_objs[j].send(shares[j][k].to_bytes(num_bytes, sys.byteorder))

                else: # send data to server 2 and server 3
                    # the first share is the seed 
                    loggers[i].info('send the seed and shares to server '+str(i+1)+'...')
                    length = (shares[j][0].bit_length() + 7) // 8
                    loggers[i].info('send length of the seed...')
                    socket_objs[j].send(length.to_bytes(4, sys.byteorder))
                    loggers[i].info('send the seed...')
                    socket_objs[j].send(shares[j][0].to_bytes(length, sys.byteorder))
                    loggers[i].info('send the shares...')
                    length = (shares[j][1][0].item().bit_length() + 7) // 8
                    if length == 0: length = 1
                    loggers[i].info('send the length of each share...')            
                    socket_objs[j].send(length.to_bytes(4, sys.byteorder))
                    loggers[i].info('send the number of shares in each dimension...')
                    num_shares_of_each_dimension = len(shares[j][1])
                    socket_objs[j].send(num_shares_of_each_dimension.to_bytes(1, sys.byteorder))
                    for k in range(1,num_shares):
                        for l in range(len(shares[j][k])):
                            socket_objs[j].send(shares[j][k][l].item().to_bytes(length, sys.byteorder))

            for k in range(data_dimension):
                # send shares of beaver multiplication triples to server 1
                    socket_objs[0].send(shares_of_ais[i]['to_S1'][k][0].to_bytes(num_bytes, sys.byteorder))
                    socket_objs[0].send(shares_of_ais[i]['to_S1'][k][1].to_bytes(num_bytes, sys.byteorder))
                    socket_objs[0].send(shares_of_cis[i]['to_S1'][k][0].to_bytes(num_bytes, sys.byteorder))
                    socket_objs[0].send(shares_of_cis[i]['to_S1'][k][1].to_bytes(num_bytes, sys.byteorder))

                # send shares of beaver multiplication triples to server 2 
                    socket_objs[1].send(shares_of_ais[i]['to_S2'][k][0].to_bytes(num_bytes, sys.byteorder))
                    socket_objs[1].send(shares_of_ais[i]['to_S2'][k][1].to_bytes(num_bytes, sys.byteorder))
                    socket_objs[1].send(shares_of_cis[i]['to_S2'][k][0].to_bytes(num_bytes, sys.byteorder))
                    socket_objs[1].send(shares_of_cis[i]['to_S2'][k][1].to_bytes(num_bytes, sys.byteorder))

                # send shares of beaver multiplication triples to server 3
                    socket_objs[2].send(shares_of_ais[i]['to_S3'][k][0].to_bytes(num_bytes, sys.byteorder))
                    socket_objs[2].send(shares_of_ais[i]['to_S3'][k][1].to_bytes(num_bytes, sys.byteorder))
                    socket_objs[2].send(shares_of_cis[i]['to_S3'][k][0].to_bytes(num_bytes, sys.byteorder))
                    socket_objs[2].send(shares_of_cis[i]['to_S3'][k][1].to_bytes(num_bytes, sys.byteorder))

            if i == 0:
                for j in range(3):
                    # send shares of l2 norm bound 
                    for k in range(2):
                        if j == 0:
                            socket_objs[j].send(shares_of_l2_norm_bound['to_S1'][k].to_bytes(num_bytes, sys.byteorder))
                        elif j == 1:
                            socket_objs[j].send(shares_of_l2_norm_bound['to_S2'][k].to_bytes(num_bytes, sys.byteorder))
                        else:
                            socket_objs[j].send(shares_of_l2_norm_bound['to_S3'][k].to_bytes(num_bytes, sys.byteorder))

        else:
            # except the 1st round, clients receive shares of aggregation from servers,
            # then recover the results and continue to train 
            pass


#     # update global model 
#     net_glob.load_state_dict(w_glob)

#     # train/test accuracy
#     acc_avg_train = sum(acc_train_local) / len(acc_train_local)
#     acc_train_all.append(acc_avg_train)
#     acc_avg_test = sum(acc_test_local) / len(acc_test_local)
#     acc_test_all.append(acc_avg_test)

#     # train/test loss
#     loss_avg_train = sum(loss_train_local) / len(loss_train_local)
#     loss_train_all.append(loss_avg_train)
#     loss_avg_test = sum(loss_test_local) / len(loss_test_local)
#     loss_test_all.append(loss_avg_test)

#     print('------------------- SERVER ----------------------------------------------')
#     print('Train: Round {:3d}, Avg Accuracy {:.3f} | Avg Loss {:.3f}'.format(epoch, acc_avg_train, loss_avg_train))
#     print('Test:  Round {:3d}, Avg Accuracy {:.3f} | Avg Loss {:.3f}'.format(epoch, acc_avg_test, loss_avg_test))
#     print('-------------------------------------------------------------------------')

# print("Training and Evaluation completed!")    

# # Save output data to .excel file (we use for comparision plots)
# round_process = [i for i in range(1, len(acc_train_all)+1)]
# df = DataFrame({'round': round_process,'acc_train':acc_train_all, 'acc_test':acc_test_all})     
# file_name = program+".xlsx"    
# df.to_excel(file_name, sheet_name= "v1_test", index = False)     



    


    