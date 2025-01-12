import os
import sys
import time
import random 
import logging
import coloredlogs
import socket 
import threading
import socketserver
import numpy as np
from bitarray import bitarray
from concurrent.futures import ProcessPoolExecutor
from cryptography.hazmat.primitives import hashes, hmac
from Utility import recv_exactly, int_to_twos_complement, \
    int_from_twos_complement, read_arbitrary_bit_length, process_chunk

coloredlogs.install(level='DEBUG')
logging.basicConfig(level=logging.DEBUG,
                    format='%(name)s: %(message)s',
                    )

# component-wise bounding parameter L 
L = 256
# setup materials
setup_materials = {'keys': [(b'\xf7\xb0\x91\xc8\xdf\x81\r\xd1', b'\x83<G\xd8?\rG}', b'\x11\xab\x14sO\\\x17X'),(b'\xf7\xb0\x91\xc8\xdf\x81\r\xd1', b'\xc2\xa7\xe1\xb2,\x08\xe58', b'\x11\xab\x14sO\\\x17X'),(b'\xc2\xa7\xe1\xb2,\x08\xe58', b'\x83<G\xd8?\rG}', b'\x11\xab\x14sO\\\x17X')],
                   'PRF_counters': [[14946496669844502460, 12922771947244445395, 12301499682450725286], [14946496669844502460, 3500725044436648833, 12301499682450725286], [3500725044436648833, 12922771947244445395, 12301499682450725286]]}

# generate two random values to test the multiplication protocol 
# x = 150
# y = 4
# x_12,x_13,x_23 = 100,45,5
# y_12,y_13,y_23 = 1,1,2

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, id, num_clients, offline, generate, dimension, upperbound, address, handler_class):
        self.id = id
        self.offline = offline # True or False
        self.port = address[1]
        self.peers = {}
        if self.id == 1:
            self.peers['2'] = self.port + 1
            self.peers['3'] = self.port + 2
            # self.x_shares = (x_12,x_13)
            # self.y_shares = (y_12,y_13)
        elif self.id == 2:
            self.peers['1'] = self.port - 1
            self.peers['3'] = self.port + 1
            # self.x_shares = (x_12,x_23)
            # self.y_shares = (y_12,y_23)
        else:
            self.peers['1'] = self.port - 2
            self.peers['2'] = self.port - 1
            # self.x_shares = (x_23,x_13)
            # self.y_shares = (y_23,y_13)
        self.keys = setup_materials['keys'][id-1]
        self.PRF_counters = setup_materials['PRF_counters'][id-1]
        self.num_clients = num_clients
        self.generate = generate
        self.ring_size = 0
        self.num_bytes = 0
        self.mask = 0
        self.client_data = {}
        self.shares = {}
        self.views_to_send = {}
        self.views_to_comp = {}
        self.view_received = b''
        self.data_dimension = dimension
        self.data_upperbound = upperbound
        self.num_clients_data_received = 0
        self.shares_of_l2_norm = {}
        self.received_shares_of_l2_norm = {}
        self.received_beta13_for_share_conversion = {} # used by Server 3 
        self.is_uploading_done = False
        self.is_handshaking_done = False
        self.is_receive_view_of_inputs_done = False
        self.is_input_batchcheck_done = False
        self.is_component_wise_bounding_done = False
        self.is_correlated_tuples_generation_done = False
        self.is_local_computation_of_correlated_tuples_generation_done = False
        self.is_server2_ready_for_share_conversion_phase1 = False
        self.is_server3_ready_for_share_conversion_phase1 = False
        self.is_ready_for_share_conversion_phase2 = False
        self.is_share_conversion_phase1_done = False # used by server 1
        self.is_share_conversion_done = False
        self.is_norm_share_computation_done = False
        self.is_norm_computaion_done = False
        self.is_multiplication_done = False
        self.is_receive_multiplication_share_done = False
        self.is_receive_zetas_done = False
        self.is_receive_l2norm_share_done = False
        self.final_converted_arithmetic_shares = {}
        self.share_mu2 = [0,0]
        self.gammas = {} # used by server 2 and server 3
        self.deltas = {}
        self.zs = {}
        self.shares_of_l2_norm = {}
        self.received_shares_of_differences = {}
        self.view_of_difference = b''
        self.received_view_of_difference = b''
        self.is_receive_shares_of_differences_done = False
        self.is_receive_view_of_difference_done = False
        self.differences = {}
        self.running_time = {}
        self.running_time['share_recovery'] = 0
        self.is_receive_share_beta13_done = False # used by Server 3
        # filenames 
        if self.id == 1:
            self.filename_betas = ''
            self.filename_beta_shares12 = ''
            self.filename_beta_shares13 = ''
            self.filename_sigma_shares12 = ''
            self.filename_sigma_shares13 = ''
        else:
            self.filename_alphas = ''
            if self.id == 2:
                self.filename_beta_shares12 = ''
                self.filename_beta_shares23 = ''
                self.filename_sigma_shares12 = ''
                self.filename_sigma_shares23 = ''
            else:
                self.filename_beta_shares23 = ''
                self.filename_beta_shares13 = ''
                self.filename_sigma_shares23 = ''
                self.filename_sigma_shares13 = ''
        self.filename_epsilon_shares1 = ''
        self.filename_epsilon_shares2 = ''
        self.logger = logging.getLogger('Server '+str(id))
        self.logger.info('initialize')
        socketserver.TCPServer.__init__(self, server_address=address, RequestHandlerClass=handler_class)
        self.timeout = 5
    
    def process_request(self, request, client_address):
        request.settimeout(self.timeout)
        return socketserver.TCPServer.process_request(self, request, client_address)

    def serve_forever(self):
        self.logger.info('serve_forever')
        while True:
            self.handle_request()
            # if the uploading is done, connect to peers
            if self.is_uploading_done == True and self.id == 2 and self.is_handshaking_done == False:
                self.is_handshaking_done = True
                self.logger.info('send shakehanding requests to peers...')
                port_server1, _ = self.peers.values()
                thread = threading.Thread(target=self.handshaking_and_batchchecking, args=(port_server1,))
                self.logger.info('shakehand with peer server 1.')
                thread.start()

            if self.is_uploading_done == True and self.id == 3 and self.is_handshaking_done == False:
                self.is_handshaking_done = True 
                self.logger.info('send shakehanding requests to peers...')
                port_server1, port_server2 = self.peers.values()
                thread1 = threading.Thread(target=self.handshaking_and_batchchecking, args=(port_server1,1))
                thread2 = threading.Thread(target=self.handshaking_and_batchchecking, args=(port_server2,2))
                self.logger.info('shakehand with peer server 1.')
                thread1.start()
                self.logger.info('shakehand with peer server 2.')
                thread2.start()

            if self.is_uploading_done == True and self.is_receive_view_of_inputs_done == True and self.is_input_batchcheck_done == False:
                if self.view_received == self.views_to_comp['inputs']:
                    self.logger.info('the view of inputs is consistent.')
                else:
                    self.logger.error('the view of inputs is inconsistent!')
                    self.logger.error('view received from the peer:%s',self.view_received)
                    self.logger.error('view received from the client:%s',self.views_to_comp['inputs'])

                self.is_receive_view_of_inputs_done = False
                self.is_input_batchcheck_done = True

            if self.is_input_batchcheck_done == True:
                self.is_input_batchcheck_done = False
                self.logger.info('enter the second phase: norm-bounding based selection...')
                self.logger.info('start to enforce component wise bounding...')
                thread = threading.Thread(target=self.component_wise_bounding, args=())
                thread.start()

            if self.is_component_wise_bounding_done == True:
                self.is_component_wise_bounding_done = False
                if self.offline == 0:
                    self.logger.info('start to generate correlated random tuples for share conversion...')
                    thread = threading.Thread(target=self.generate_correlated_tuples, args=())
                    thread.start()
                else:
                    self.logger.info('use precomputed correlated random tuples for share conversion.')
                    self.is_correlated_tuples_generation_done = True 

                    # server 2 and server 3 notify server 1 that they are ready for share conversion 
                    if self.id != 1:
                        s1_address = ('localhost',self.peers['1'])
                        socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                        socket_obj.connect(s1_address)
                        if self.id == 2:
                            request = 'SERVER-2-READYCONVER'
                        else:
                            request = 'SERVER-3-READYCONVER'
                        socket_obj.send(request.encode())
                        response = socket_obj.recv(5)
                        assert response.decode() == 'check'

            if self.is_local_computation_of_correlated_tuples_generation_done == True:
                if self.id == 3:
                    if self.is_receive_share_beta13_done == True:
                        self.is_local_computation_of_correlated_tuples_generation_done = False
                        self.logger.info('computing sharings of epsilons via multiplication protocol...')

                        thread = threading.Thread(target=self.semihonest_multiplication_batch,args=())
                        thread.start()
                else:
                    self.is_local_computation_of_correlated_tuples_generation_done = False
                    self.logger.info('computing 3-out-of-3 additive sharings of epsilons via multiplication protocol...')

                    thread = threading.Thread(target=self.semihonest_multiplication_batch,args=())
                    thread.start()

            if self.is_multiplication_done == True and self.is_receive_multiplication_share_done == True:
                self.is_multiplication_done = False
                self.is_receive_multiplication_share_done = False 
                self.logger.info('combine shares of epsilons done.')
                self.logger.info('generate correlated random tuples for share conversion done.')

                self.is_correlated_tuples_generation_done = True

                # server 2 and server 3 notify server 1 that they are ready for share conversion 
                if self.id != 1:
                    s1_address = ('localhost',self.peers['1'])
                    socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                    socket_obj.connect(s1_address)
                    if self.id == 2:
                        request = 'SERVER-2-READYCONVER'
                    else:
                        request = 'SERVER-3-READYCONVER'
                    socket_obj.send(request.encode())
                    response = socket_obj.recv(5)
                    assert response.decode() == 'check'

                # delete intermediate results
                if self.id == 1:
                    os.remove(self.filename_beta_shares12)
                    os.remove(self.filename_beta_shares13)
                    os.remove(self.filename_sigma_shares12)
                    os.remove(self.filename_sigma_shares13)
                elif self.id == 2:
                    os.remove(self.filename_beta_shares12)
                    os.remove(self.filename_beta_shares23)
                    os.remove(self.filename_sigma_shares12)
                    os.remove(self.filename_sigma_shares23)
                else:
                    os.remove(self.filename_beta_shares23)
                    os.remove(self.filename_beta_shares13)
                    os.remove(self.filename_sigma_shares23)
                    os.remove(self.filename_sigma_shares13)

                # used for debug 
                # for client_id in self.yis_in_multiplication_protocol.keys():
                #     for i in range(self.data_dimension):
                #             if self.id == 1:
                #                 self.logger.debug('client: %s, dimension: %s, share0 of epsilons:\n%s\n',client_id,i+1,self.yis_in_multiplication_protocol[client_id][i])
                #                 self.logger.debug('share1 of epsilons:\n%s\n',self.received_yis_in_multiplication_protocol[client_id][i])
                #             else:
                #                 self.logger.debug('client: %s, dimension: %s, share0 of epsilons:\n%s\n',client_id,i+1,self.received_yis_in_multiplication_protocol[client_id][i])
                #                 self.logger.debug('share1 of epsilons:\n%s\n',self.yis_in_multiplication_protocol[client_id][i])

            if self.id == 1 and self.is_correlated_tuples_generation_done == True and self.is_server2_ready_for_share_conversion_phase1 == True and self.is_server3_ready_for_share_conversion_phase1 == True:
                # if self.generate > 0: 
                #     sys.exit()
                self.is_correlated_tuples_generation_done = False 
                self.is_server2_ready_for_share_conversion_phase1 = False
                self.is_server3_ready_for_share_conversion_phase1 = False
                self.boolean2arithmetic_conversion_phase1()

            if self.id == 1 and self.is_share_conversion_phase1_done == True:
                self.is_share_conversion_phase1_done = False
                # here compute delta = delta ^ beta 
                file_betas = open(self.filename_betas,'r+b')
                for client_id in self.deltas.keys():
                    for i in range(self.data_dimension):
                        beta = bitarray()
                        beta.frombytes(file_betas.read(self.num_bytes))
                        # self.logger.debug('dimension: %s, used beta: %s',i+1,beta)
                        self.deltas[client_id][i] = self.deltas[client_id][i] ^ beta
                file_betas.close()
                self.is_ready_for_share_conversion_phase2 = True 

            if self.is_receive_zetas_done == True: # this is server 2
                start = time.perf_counter()
                self.is_receive_zetas_done = False 
                self.logger.info('computing and sending etas to server 1...')
                s1_address = ('localhost',self.peers['1'])
                socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                socket_obj.connect(s1_address)
                request = 'SERVER-2-SENDETAS---'
                socket_obj.send(request.encode())
                file_alphas = open(self.filename_alphas,'r+b')
                for client_id in self.shares.keys():
                    socket_obj.send(client_id.encode())
                    for i in range(self.data_dimension):
                        alpha = bitarray()
                        alpha.frombytes(file_alphas.read(self.num_bytes))
                        eta = self.shares[client_id][i][1] ^ alpha
                        socket_obj.send(eta.tobytes())
                file_alphas.close()
                end = time.perf_counter()
                self.running_time['share_conversion_phase1'] += (end - start)
                self.is_ready_for_share_conversion_phase2 = True

            if self.is_ready_for_share_conversion_phase2 == True:
                self.is_ready_for_share_conversion_phase2 = False
                self.logger.info('running the second phase of share conversion, computing the targeted arithmetic shares...')
                file_epsilon_shares1 = open(self.filename_epsilon_shares1,'r+b')
                file_epsilon_shares2 = open(self.filename_epsilon_shares2,'r+b')
                start = time.perf_counter()
                for client_id in self.deltas.keys():
                    self.final_converted_arithmetic_shares[client_id] = []
                    for i in range(self.data_dimension):
                        self.final_converted_arithmetic_shares[client_id].append([0,0])
                        for j in range(self.ring_size):
                            if self.id == 1:
                                epsilon12 = int.from_bytes(file_epsilon_shares1.read(self.num_bytes),sys.byteorder)
                                self.final_converted_arithmetic_shares[client_id][i][0] = (self.final_converted_arithmetic_shares[client_id][i][0] + \
                                                                                        pow(2,j) * (pow(-1,self.deltas[client_id][i][j]) * epsilon12)) & self.mask
                                epsilon13 = int.from_bytes(file_epsilon_shares2.read(self.num_bytes),sys.byteorder)
                                self.final_converted_arithmetic_shares[client_id][i][1] = (self.final_converted_arithmetic_shares[client_id][i][1] + \
                                                                                        pow(2,j) * (pow(-1,self.deltas[client_id][i][j]) * epsilon13)) & self.mask
                            elif self.id == 2:
                                epsilon12 = int.from_bytes(file_epsilon_shares1.read(self.num_bytes),sys.byteorder)
                                self.final_converted_arithmetic_shares[client_id][i][0] = (self.final_converted_arithmetic_shares[client_id][i][0] + \
                                                                                        pow(2,j) * (pow(-1,self.deltas[client_id][i][j]) * epsilon12)) & self.mask
                                epsilon23 = int.from_bytes(file_epsilon_shares2.read(self.num_bytes),sys.byteorder)
                                self.final_converted_arithmetic_shares[client_id][i][1] = (self.final_converted_arithmetic_shares[client_id][i][1] + \
                                                                                       pow(2,j) * (pow(-1,self.deltas[client_id][i][j]) * epsilon23 + \
                                                                                                    self.gammas[client_id][i][j])) & self.mask
                            else:
                                epsilon23 = int.from_bytes(file_epsilon_shares1.read(self.num_bytes),sys.byteorder)
                                self.final_converted_arithmetic_shares[client_id][i][0] = (self.final_converted_arithmetic_shares[client_id][i][0] + \
                                                                                        pow(2,j) * (pow(-1,self.deltas[client_id][i][j]) * epsilon23 + \
                                                                                                        self.gammas[client_id][i][j])) & self.mask
                                epsilon13 = int.from_bytes(file_epsilon_shares2.read(self.num_bytes),sys.byteorder)
                                self.final_converted_arithmetic_shares[client_id][i][1] = (self.final_converted_arithmetic_shares[client_id][i][1] + \
                                                                                       pow(2,j) * (pow(-1,self.deltas[client_id][i][j]) * epsilon13)) & self.mask
                file_epsilon_shares1.close()
                file_epsilon_shares2.close()

                # with open(self.filename_epsilon_shares, 'r+b') as file_epsilon_shares:
                #     # Precompute powers of 2 to avoid redundant calculations
                #     powers_of_2 = [pow(2, j) for j in range(self.ring_size)]
                #     total_epsilon_count = self.data_dimension * self.ring_size * 2

                #     for client_id, deltas in self.deltas.items():
                #         self.final_converted_arithmetic_shares[client_id] = [
                #             [0, 0] for _ in range(self.data_dimension)]

                #         # Read all epsilon values for this client_id in one go
                #         epsilon_data = read_arbitrary_bit_length(file_epsilon_shares, self.num_bytes, total_epsilon_count)

                #         # Process epsilon values for each data dimension and ring size
                #         idx = 0
                #         for i in range(self.data_dimension):
                #             for j in range(self.ring_size):
                #                 # idx = (i * self.ring_size) + (j * 2)
                #                 delta = deltas[i][j]
                #                 power_of_2 = powers_of_2[j]
                #                 neg_factor = -1 if delta else 1

                #                 if self.id == 1:
                #                     epsilon12 = epsilon_data[idx]
                #                     idx += 1
                #                     epsilon13 = epsilon_data[idx]
                #                     idx += 1
                #                     # epsilon12 = epsilon_data[idx]
                #                     # epsilon13 = epsilon_data[idx + 1]
                #                     self.final_converted_arithmetic_shares[client_id][i][0] = (self.final_converted_arithmetic_shares[client_id][i][0] + \
                #                                                                                power_of_2 * neg_factor * epsilon12) & self.mask
                #                     self.final_converted_arithmetic_shares[client_id][i][1] = (self.final_converted_arithmetic_shares[client_id][i][1] + \
                #                                                                                power_of_2 * neg_factor * epsilon13) & self.mask
                #                 elif self.id == 2:
                #                     epsilon12 = epsilon_data[idx]
                #                     idx += 1
                #                     epsilon23 = epsilon_data[idx]
                #                     idx += 1
                #                     # epsilon12 = epsilon_data[idx]
                #                     # epsilon23 = epsilon_data[idx + 1]
                #                     self.final_converted_arithmetic_shares[client_id][i][0] = (self.final_converted_arithmetic_shares[client_id][i][0] + \
                #                                                                                power_of_2 * neg_factor * epsilon12) & self.mask
                #                     self.final_converted_arithmetic_shares[client_id][i][1] = (self.final_converted_arithmetic_shares[client_id][i][1] + \
                #                                                                                power_of_2 * (neg_factor * epsilon23 + self.gammas[client_id][i][j])) & self.mask
                #                 else:  # self.id == 3
                #                     epsilon23 = epsilon_data[idx]
                #                     idx += 1 
                #                     epsilon13 = epsilon_data[idx]
                #                     idx += 1
                #                     # epsilon23 = epsilon_data[idx]
                #                     # epsilon13 = epsilon_data[idx + 1]
                #                     self.final_converted_arithmetic_shares[client_id][i][0] = (self.final_converted_arithmetic_shares[client_id][i][0] + \
                #                                                                                power_of_2 * (neg_factor * epsilon23 + self.gammas[client_id][i][j])) & self.mask
                #                     self.final_converted_arithmetic_shares[client_id][i][1] = (self.final_converted_arithmetic_shares[client_id][i][1] + \
                #                                                                                power_of_2 * neg_factor * epsilon13) & self.mask

                end = time.perf_counter()
                self.running_time['share_conversion_phase2'] = (end - start)
    
                self.is_share_conversion_done = True

                # for debug
                # for client_id in self.final_converted_arithmetic_shares.keys():
                #     self.logger.debug('client: %s, arithmetic shares of dimension 1: %s, dimension d: %s',client_id,self.final_converted_arithmetic_shares[client_id][0],self.final_converted_arithmetic_shares[client_id][-1])

            if self.is_share_conversion_done == True:
                self.is_share_conversion_done = False
                self.logger.info('computing l2 norms...')
                self.logger.info('firstly computing 3-out-of-3 additive shares of l2 norms...')

                start = time.perf_counter()
                for client_id in self.final_converted_arithmetic_shares.keys():
                    if self.id == 1:
                        self.shares_of_l2_norm[client_id] = self.zero_sharing()
                        for i in range(self.data_dimension):
                            self.shares_of_l2_norm[client_id] = (self.shares_of_l2_norm[client_id] + pow(self.final_converted_arithmetic_shares[client_id][i][0],2) + \
                                                         2 * self.final_converted_arithmetic_shares[client_id][i][0] * self.final_converted_arithmetic_shares[client_id][i][1]) & self.mask
                    else:
                        self.shares_of_l2_norm[client_id] = self.zero_sharing()
                        for i in range(self.data_dimension):
                            self.shares_of_l2_norm[client_id] = (self.shares_of_l2_norm[client_id] + pow(self.final_converted_arithmetic_shares[client_id][i][1],2) + \
                                                         2 * self.final_converted_arithmetic_shares[client_id][i][0] * self.final_converted_arithmetic_shares[client_id][i][1]) & self.mask

                # send 3-out-of-3 additive shares to convert them to replicated shares 
                self.logger.info('sending the 3-out-of-3 additive shares of l2 norms to convert them to replicated sharings...')
                socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if self.id == 1:
                    s2_address = ('localhost',self.peers['2'])
                    socket_obj.connect(s2_address)
                    request = "SERVER-1-3OF3SHARES-"
                    socket_obj.send(request.encode())
                    for client_id in self.shares_of_l2_norm.keys():
                        socket_obj.send(client_id.encode())
                        socket_obj.send(self.shares_of_l2_norm[client_id].to_bytes(self.num_bytes, sys.byteorder))
                elif self.id == 2:
                    s3_address = ('localhost',self.peers['3'])
                    # socket_obj.connect(s3_address)
                    while True:
                        try:
                            socket_obj.connect(s3_address)
                            break
                        except ConnectionRefusedError as e:
                            self.logger.info("connection refused: %s",e)
                            self.logger.info("retrying in 3 seconds...")
                            time.sleep(3)  # Wait before retrying
                        except Exception as e:
                            self.logger.warning("an unexpected error occurred: %s",e)
                            self.logger.info("retrying in 3 seconds...")
                            time.sleep(3)  # Wait before retrying            
                    request = "SERVER-2-3OF3SHARES-"
                    socket_obj.send(request.encode())
                    for client_id in self.shares_of_l2_norm.keys():
                        socket_obj.send(client_id.encode())
                        socket_obj.send(self.shares_of_l2_norm[client_id].to_bytes(self.num_bytes, sys.byteorder))
                else:
                    s1_address = ('localhost',self.peers['1'])                    
                    socket_obj.connect(s1_address)
                    request = "SERVER-3-3OF3SHARES-"
                    socket_obj.send(request.encode())
                    for client_id in self.shares_of_l2_norm.keys():
                        socket_obj.send(client_id.encode())
                        socket_obj.send(self.shares_of_l2_norm[client_id].to_bytes(self.num_bytes, sys.byteorder))
                
                end = time.perf_counter()
                self.running_time['l2_norm_computation'] = (end - start)
                self.logger.info('send the 3-out-of-3 additive shares of l2 norms to convert them to replicated sharings done.')
                self.is_norm_share_computation_done = True

            if self.is_norm_share_computation_done == True and self.is_receive_l2norm_share_done == True:
                self.is_norm_share_computation_done = False
                self.is_receive_l2norm_share_done = False
                self.logger.info('converting 3-out-of-3 shares of l2 norms to replicated shares...')
                start = time.perf_counter()
                for client_id in self.shares_of_l2_norm.keys():
                    if self.id == 1:
                        self.shares_of_l2_norm[client_id] = (self.shares_of_l2_norm[client_id], self.received_shares_of_l2_norm[client_id])
                    else:
                        self.shares_of_l2_norm[client_id] = (self.received_shares_of_l2_norm[client_id], self.shares_of_l2_norm[client_id])
                end = time.perf_counter()
                self.running_time['l2_norm_computation'] += (end - start)
                self.is_norm_computaion_done = True
                # for debug 
                # for client_id in self.shares_of_l2_norm.keys():
                #     self.logger.debug('client: %s, shares of its l2 norm: %s',client_id,self.shares_of_l2_norm[client_id])

            # enforce l2 norm bounding 
            if self.is_norm_computaion_done == True: 
                self.is_norm_computaion_done = False
                self.logger.info('computing shares of differences between l2 norms and the bound...')
                # self.logger.debug('shares of mu2: %s',self.share_mu2)
                start = time.perf_counter()
                for client_id in self.shares_of_l2_norm.keys():
                    self.zs[client_id] = ((self.shares_of_l2_norm[client_id][0] - self.share_mu2[0]) & self.mask,\
                                          (self.shares_of_l2_norm[client_id][1] - self.share_mu2[1]) & self.mask) 

                # open the differences to enforce the norm bounding 
                if self.id == 1:
                    address = ('localhost',self.peers['2'])
                    request = "SERVER-1-OPENDIFFERE"
                elif self.id == 2:
                    address = ('localhost',self.peers['3'])
                    request = "SERVER-2-OPENDIFFERE"
                else:
                    address = ('localhost',self.peers['1'])
                    request = "SERVER-3-OPENDIFFERE"
                socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket_obj.connect(address)
                socket_obj.send(request.encode())

                for client_id in self.zs.keys():
                    socket_obj.send(client_id.encode())
                    if self.id == 1:
                        socket_obj.send(self.zs[client_id][1].to_bytes(self.num_bytes, sys.byteorder))
                    else:
                        socket_obj.send(self.zs[client_id][0].to_bytes(self.num_bytes, sys.byteorder))

                end = time.perf_counter()
                self.running_time['l2_norm_bounding'] = (end - start)

            if self.is_receive_shares_of_differences_done == True:
                self.is_receive_shares_of_differences_done = False
                self.logger.info('checking the view of differences...')
                bytes = b''
                for client_id in self.zs.keys():
                    self.differences[client_id] = (self.zs[client_id][0] + self.zs[client_id][1] + self.received_shares_of_differences[client_id]) & self.mask
                    bytes += self.differences[client_id].to_bytes(self.num_bytes, sys.byteorder)
                hash_obj = hashes.Hash(hashes.SHA256())
                hash_obj.update(bytes)
                self.view_of_difference = hash_obj.finalize()
                if self.id == 1:
                    address = ('localhost',self.peers['2'])
                    request = "SERVER-1-VIEWDIFFERE"
                elif self.id == 2:
                    address = ('localhost',self.peers['3'])
                    request = "SERVER-2-VIEWDIFFERE"
                else:
                    address = ('localhost',self.peers['1'])
                    request = "SERVER-3-VIEWDIFFERE"
                socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                socket_obj.connect(address)
                socket_obj.send(request.encode())
                socket_obj.send(self.view_of_difference)

            if self.is_receive_view_of_difference_done == True:
                self.is_receive_view_of_difference_done = False 
                if self.view_of_difference == self.received_view_of_difference:
                    self.logger.info('the view of differences is consistent.')
                    self.logger.info('aggregating data of benign clients...')
                    start = time.perf_counter()
                    aggregation = [[0,0] for i in range(self.data_dimension)]
                    num_clients_involved = 0
                    for client_id in self.differences.keys():
                        # self.logger.debug('arithmetic shares of data of client %s:\n%s',client_id,self.final_converted_arithmetic_shares[client_id])
                        difference = int_from_twos_complement(int_to_twos_complement(self.differences[client_id], self.ring_size), self.ring_size)
                        # self.logger.debug('difference of client %s: %s', client_id,difference)
                        if difference <= 0:
                            for i in range(self.data_dimension):
                                aggregation[i][0] = (aggregation[i][0] + self.final_converted_arithmetic_shares[client_id][i][0]) & self.mask
                                aggregation[i][1] = (aggregation[i][1] + self.final_converted_arithmetic_shares[client_id][i][1]) & self.mask
                            num_clients_involved += 1
                    # division 
                    # aggregation_array = np.array(aggregation, dtype=object)
                    # aggregation = aggregation_array // num_clients_involved
                    end = time.perf_counter()
                    self.running_time['aggregation'] = (end - start)
                    self.logger.debug('dimension 1 of aggregation: %s dimension n of aggregation: %s',aggregation[0],aggregation[-1])

                    for key, item in self.running_time.items():
                        self.logger.debug('%s: %ss',key,item)
                    sys.exit()
                else:
                    self.logger.error('the view of differences is inconsistent.')
                    sys.exit()

    def handle_request(self):
        self.logger.info('waiting for request...')
        return socketserver.TCPServer.handle_request(self)
    
    def handshaking_and_batchchecking(self, port_of_peer: int, peer_id: int = 1):
        peer_address = ('localhost', port_of_peer)
        socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_obj.connect(peer_address)        
        # send shakehanding request 
        if self.id == 2:
            request = 'SERVER-2-SHAKEHAND--'
            socket_obj.send(request.encode())
            # receive the response from peer 
            response = recv_exactly(socket_obj,5)
            if response.decode() == 'check':
                self.logger.info('shakehand with peer done.')
            else:
                self.logger.error('failed to shakehand with peer.')
            # receive the batch-check request from server 1
            response = recv_exactly(socket_obj,20)
            assert response.decode() == "SERVER-1-BATCHCHECK-"
            # receive the 32-byte view 
            self.view_received = recv_exactly(socket_obj,32)
            # self.logger.debug('view received:%s',self.view_received)

            self.is_receive_view_of_inputs_done = True

        elif self.id == 3:
            assert peer_id == 1 or peer_id == 2
            request = 'SERVER-3-SHAKEHAND--'
            socket_obj.send(request.encode())
            # receive the response from peer 
            response = recv_exactly(socket_obj,5)
            if response.decode() == 'check':
                self.logger.info('shakehand with peer done.')
            else:
                self.logger.error('failed to shakehand with peer.')

            if peer_id == 1:
                request = "SERVER-3-BATCHCHECK-"
                socket_obj.send(request.encode())
                # Server 3 sends view of inputs to Server 1
                socket_obj.send(self.views_to_send['inputs'])
            else:
                request = recv_exactly(socket_obj,20).decode()
                assert request == "SERVER-2-BATCHCHECK-"
                self.view_received = recv_exactly(socket_obj,32)
                # self.logger.debug('view received:%s',self.view_received)

                self.is_receive_view_of_inputs_done = True

    def component_wise_bounding(self):
        result = True
        start = time.perf_counter()
        for client_id in self.shares.keys():
            for i in range(self.data_dimension):
                if len(self.shares[client_id][i][0]) <= L and len(self.shares[client_id][i][1]) <= L:
                    pass
                else:
                    result = False
                    self.logger.error('bit length of input boolean shares exceeds the bound!')
                    sys.exit(1)
        if result == True:
            self.logger.info('component wise bounding: pass.')
        end = time.perf_counter()
        self.running_time['component_wise_bounding'] = (end - start)
        self.is_component_wise_bounding_done = True

    def generate_correlated_tuples(self):
        # write alphas or betas to a file 
        if self.id == 1:
            file_betas = open(self.filename_betas, 'w+b')
        else:
            file_alphas = open(self.filename_alphas, 'w+b')
        if self.id == 1:
            file_beta_shares12 = open(self.filename_beta_shares12, 'w+b')
            file_beta_shares13 = open(self.filename_beta_shares13, 'w+b')
            file_sigma_shares12 = open(self.filename_sigma_shares12, 'w+b')
            file_sigma_shares13 = open(self.filename_sigma_shares13, 'w+b')
        elif self.id == 2:
            file_beta_shares12 = open(self.filename_beta_shares12, 'w+b')
            file_beta_shares23 = open(self.filename_beta_shares23, 'w+b')
            file_sigma_shares12 = open(self.filename_sigma_shares12, 'w+b')
            file_sigma_shares23 = open(self.filename_sigma_shares23, 'w+b')
        else:
            file_beta_shares23 = open(self.filename_beta_shares23, 'w+b')
            file_sigma_shares23 = open(self.filename_sigma_shares23, 'w+b')
            file_sigma_shares13 = open(self.filename_sigma_shares13, 'w+b')
        for client_id in self.shares.keys():
            for i in range(self.data_dimension):
                alpha_dimension_i = bitarray()
                beta_dimension_i = bitarray()
                for j in range(self.ring_size):
                    if self.id == 1:
                        # S1 randomly selects a bit \beta
                        beta = random.getrandbits(1)
                        beta_dimension_i.append(beta)

                        # S1,S2 jointly generate share [\beta]_{12}
                        ctr12_bytes = self.PRF_counters[0].to_bytes(8, sys.byteorder)
                        hmac_obj = hmac.HMAC(self.keys[0], hashes.SHA256())
                        hmac_obj.update(ctr12_bytes)
                        beta_12 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        # if client_id == '0001':
                        #     self.logger.debug('client: %s, dimension: %s, bit index: %s, correct beta_share12: %s',client_id,i+1,j+1,beta_12)
                        self.PRF_counters[0] += 1

                        # S1,S2,S3 jointly generate share [\beta]_{23}
                        ctrS_bytes = self.PRF_counters[2].to_bytes(8, sys.byteorder)
                        hmac_obj = hmac.HMAC(self.keys[2], hashes.SHA256())
                        hmac_obj.update(ctrS_bytes)
                        beta_23 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        self.PRF_counters[2] += 1

                        # S1 computes share [\beta]_{13}
                        beta_13 = (beta - beta_12 - beta_23) & self.mask

                        # compute [\sigma]= 1-2\cdot[\alpha]
                        sigma12, sigma13 = 1,0

                        # write intermediate results to files 
                        file_beta_shares12.write(beta_12.to_bytes(self.num_bytes,sys.byteorder))
                        file_beta_shares13.write(beta_13.to_bytes(self.num_bytes,sys.byteorder))
                        file_sigma_shares12.write(sigma12.to_bytes(self.num_bytes,sys.byteorder))
                        file_sigma_shares13.write(sigma13.to_bytes(self.num_bytes,sys.byteorder))

                    elif self.id == 2:
                        # S2,S3 jointly select bit \alpha
                        ctr23_bytes = self.PRF_counters[1].to_bytes(8, sys.byteorder)
                        hmac_obj = hmac.HMAC(self.keys[1], hashes.SHA256())
                        hmac_obj.update(ctr23_bytes)
                        alpha = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & 1
                        alpha_dimension_i.append(alpha)
                        self.PRF_counters[1] += 1

                        # S2 sets its share of alpha to (0,alpha)
                        sigma12 = 1
                        sigma23 = (0 - 2 * alpha) & self.mask

                        # S1,S2 jointly generate share [\beta]_{12}
                        ctr12_bytes = self.PRF_counters[0].to_bytes(8, sys.byteorder)
                        hmac_obj = hmac.HMAC(self.keys[0], hashes.SHA256())
                        hmac_obj.update(ctr12_bytes)
                        beta_12 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        self.PRF_counters[0] += 1

                        # S1,S2,S3 jointly generate share [\beta]_{23}
                        ctrS_bytes = self.PRF_counters[2].to_bytes(8, sys.byteorder)
                        hmac_obj = hmac.HMAC(self.keys[2], hashes.SHA256())
                        hmac_obj.update(ctrS_bytes)
                        beta_23 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        self.PRF_counters[2] += 1

                        # write intermediate results to files 
                        file_beta_shares12.write(beta_12.to_bytes(self.num_bytes,sys.byteorder))
                        file_beta_shares23.write(beta_23.to_bytes(self.num_bytes,sys.byteorder))
                        file_sigma_shares12.write(sigma12.to_bytes(self.num_bytes,sys.byteorder))
                        file_sigma_shares23.write(sigma23.to_bytes(self.num_bytes,sys.byteorder))

                    else:
                        # S2,S3 jointly select bit \alpha 
                        ctr23_bytes = self.PRF_counters[0].to_bytes(8, sys.byteorder)
                        hmac_obj = hmac.HMAC(self.keys[0], hashes.SHA256())
                        hmac_obj.update(ctr23_bytes)
                        alpha = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & 1
                        alpha_dimension_i.append(alpha)
                        self.PRF_counters[0] += 1

                        # S3 sets its share of alpha to (alpha,0)
                        sigma23 = (0 - 2 * alpha) & self.mask
                        sigma13 = 0

                        # S1,S2,S3 jointly generate share [\beta]_{23}
                        ctrS_bytes = self.PRF_counters[2].to_bytes(8, sys.byteorder)
                        hmac_obj = hmac.HMAC(self.keys[2], hashes.SHA256())
                        hmac_obj.update(ctrS_bytes)
                        beta_23 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        self.PRF_counters[2] += 1

                        # write intermediate results to files 
                        file_beta_shares23.write(beta_23.to_bytes(self.num_bytes,sys.byteorder))
                        file_sigma_shares23.write(sigma23.to_bytes(self.num_bytes,sys.byteorder))
                        file_sigma_shares13.write(sigma13.to_bytes(self.num_bytes,sys.byteorder))

                if self.id == 1:
                    # self.logger.debug('dimension: %s, correct beta: %s',i+1,beta_dimension_i)
                    file_betas.write(beta_dimension_i.tobytes())
                else:
                    # self.logger.debug('dimension: %s, correct alpha: %s',i+1,alpha_dimension_i)
                    file_alphas.write(alpha_dimension_i.tobytes())

        # S1 sends [\beta]_{13} to S3
        if self.id == 1:
            file_beta_shares13.close()
            file_beta_shares13 = open(self.filename_beta_shares13, 'r+b')
            self.logger.info('sending shares beta13 to Server3...')
            s3_address = ('localhost',self.peers['3'])
            socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # socket_obj.connect(s3_address)
            while True:
                try:
                    self.logger.info('connecting to server 3 to send it beta_13s...')
                    socket_obj.connect(s3_address)
                    self.logger.info('successfully connect to server 3.')
                    break
                except ConnectionRefusedError as e:
                    self.logger.info("connection refused: %s",e)
                    self.logger.info("retrying in 3 seconds...")
                    time.sleep(3)  # Wait before retrying
                except Exception as e:
                    self.logger.warning("an unexpected error occurred: %s",e)
                    self.logger.info("retrying in 3 seconds...")
                    time.sleep(3)  # Wait before retrying            
            request = "SERVER-1-BETASHARES-"
            socket_obj.send(request.encode())
            for client_id in self.shares.keys():
                for i in range(self.data_dimension):
                    for j in range(self.ring_size):
                        socket_obj.send(file_beta_shares13.read(self.num_bytes))
            # close files 
            file_betas.close()
            file_beta_shares12.close()
            file_beta_shares13.close()
            file_sigma_shares12.close()
            file_sigma_shares13.close()
        elif self.id == 2:
            file_alphas.close()
            file_beta_shares12.close()
            file_beta_shares23.close()
            file_sigma_shares12.close()
            file_sigma_shares23.close()
        else:
            file_alphas.close()
            file_beta_shares23.close()
            file_sigma_shares23.close()
            file_sigma_shares13.close()
    
        self.is_local_computation_of_correlated_tuples_generation_done = True

    def boolean2arithmetic_conversion_phase1(self):
        # server 1 computes and sends \zetas to server 2 and server 3
        self.logger.info('running the first phase of share conversion, computing and sending zetas...')
        s2_address = ('localhost',self.peers['2'])
        s3_address = ('localhost',self.peers['3'])
        socket_obj_s2 = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        socket_obj_s3 = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        socket_obj_s2.connect(s2_address)
        socket_obj_s3.connect(s3_address)
        request = 'SERVER-1-SENDZETAS--'
        socket_obj_s2.send(request.encode())
        socket_obj_s3.send(request.encode())

        # file_betas = open(self.filename_betas,'r+b')
        # for client_id in self.shares.keys():
        #     socket_obj_s2.send(client_id.encode())
        #     socket_obj_s3.send(client_id.encode())
        #     for i in range(self.data_dimension):
        #         beta_i = bitarray()
        #         beta_i.frombytes(file_betas.read(self.num_bytes))
        #         # self.logger.debug('dimension: %s, used beta: %s',i+1,beta_i)
        #         zeta_i = self.shares[client_id][i][0] ^ self.shares[client_id][i][1] ^ beta_i
        #         # self.logger.debug('dimension: %s, correct zeta: %s',i+1,zeta_i)
        #         socket_obj_s2.send(zeta_i.tobytes())
        #         socket_obj_s3.send(zeta_i.tobytes())
        # file_betas.close()
        
        start = time.perf_counter()
        with open(self.filename_betas, 'r+b') as file_betas:
            chunk_size = 1000  # Number of dimensions to process in a batch

            for client_id in self.shares.keys():
                socket_obj_s2.send(client_id.encode())
                socket_obj_s3.send(client_id.encode())

                # Process data_dimension in chunks
                dimension_index = 0
                for start_idx in range(0, self.data_dimension, chunk_size):
                    end_idx = min(start_idx + chunk_size, self.data_dimension)

                    # Read all beta values for the current chunk
                    beta_chunk = bitarray()
                    beta_chunk.frombytes(file_betas.read(self.num_bytes * (end_idx - start_idx)))

                    # Initialize a list to accumulate zeta values for the chunk
                    zeta_chunk = bitarray()

                    # Process the chunk
                    for i in range(start_idx, end_idx):
                        beta_i = beta_chunk[(i - start_idx) * self.num_bytes * 8 : (i - start_idx + 1) * self.num_bytes * 8]
                        zeta_i = self.shares[client_id][dimension_index][0] ^ self.shares[client_id][dimension_index][1] ^ beta_i
                        zeta_chunk.extend(zeta_i)
                        dimension_index += 1

                        # Optionally log debugging info
                        # self.logger.debug('dimension: %s, correct zeta: %s', i + 1, zeta_i)

                    # Send the entire zeta_chunk for this batch
                    socket_obj_s2.send(zeta_chunk.tobytes())
                    socket_obj_s3.send(zeta_chunk.tobytes())
        end = time.perf_counter()
        self.running_time['share_conversion_phase1'] = (end - start)
        self.logger.info('run the first phase of share conversion done.')
   
    def zero_sharing(self) -> int:
        if self.id == 1:
            ctr12_bytes = self.PRF_counters[0].to_bytes(8, sys.byteorder)
            hmac_obj = hmac.HMAC(self.keys[0], hashes.SHA256())
            hmac_obj.update(ctr12_bytes)
            F_k12_ctr12 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
            self.PRF_counters[0] += 1

            ctr13_bytes = self.PRF_counters[1].to_bytes(8, sys.byteorder)
            hmac_obj = hmac.HMAC(self.keys[1], hashes.SHA256())
            hmac_obj.update(ctr13_bytes)
            F_k13_ctr13 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
            self.PRF_counters[1] += 1

            alpha = (F_k12_ctr12 - F_k13_ctr13) & self.mask
            return alpha
        else:
            ctr1_bytes = self.PRF_counters[1].to_bytes(8, sys.byteorder)
            hmac_obj = hmac.HMAC(self.keys[1], hashes.SHA256())
            hmac_obj.update(ctr1_bytes)
            F_k1_ctr1 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
            self.PRF_counters[1] += 1

            ctr2_bytes = self.PRF_counters[0].to_bytes(8, sys.byteorder)
            hmac_obj = hmac.HMAC(self.keys[0], hashes.SHA256())
            hmac_obj.update(ctr2_bytes)
            F_k2_ctr2 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
            self.PRF_counters[0] += 1

            share = (F_k1_ctr1 - F_k2_ctr2) & self.mask
            return share
        
    def semihonest_multiplication_batch(self):
        if self.id == 1 or self.id == 2:
            file_beta_share12 = open(self.filename_beta_shares12,'r+b')
            file_sigma_share12 = open(self.filename_sigma_shares12,'r+b')
        if self.id == 1 or self.id == 3:
            file_beta_share13 = open(self.filename_beta_shares13,'r+b')
            file_sigma_share13 = open(self.filename_sigma_shares13,'r+b')
        if self.id == 2 or self.id == 3:
            file_beta_share23 = open(self.filename_beta_shares23,'r+b') 
            file_sigma_share23 = open(self.filename_sigma_shares23,'r+b')
        if self.id == 1:
            file_epsilon_shares = open(self.filename_epsilon_shares1,'w+b')
        else:
            file_epsilon_shares = open(self.filename_epsilon_shares2,'w+b')
        
        for client_id in self.shares.keys():
            for i in range(self.data_dimension):
                for j in range(self.ring_size):
                    y_i = self.zero_sharing()
                    # self.logger.debug('client: %s, dimension: %s, bit index: %s, zero_share: %s',client_id,i+1,j+1,y_i)
                    if self.id == 1:
                        beta_share12 = int.from_bytes(file_beta_share12.read(self.num_bytes),sys.byteorder)
                        beta_share13 = int.from_bytes(file_beta_share13.read(self.num_bytes),sys.byteorder)
                        # if client_id == '0001': self.logger.debug('client: %s, dimension: %s, bit index: %s, used beta_share12: %s',client_id,i+1,j+1,beta_share12)
                        sigma_share12 = int.from_bytes(file_sigma_share12.read(self.num_bytes),sys.byteorder)
                        sigma_share13 = int.from_bytes(file_sigma_share13.read(self.num_bytes),sys.byteorder)
                        y_i = (y_i +  beta_share12 * sigma_share12 + beta_share12 * sigma_share13 + beta_share13 * sigma_share12) & self.mask
                    elif self.id == 2:
                        beta_share23 = int.from_bytes(file_beta_share23.read(self.num_bytes),sys.byteorder)
                        beta_share12 = int.from_bytes(file_beta_share12.read(self.num_bytes),sys.byteorder)
                        sigma_share23 = int.from_bytes(file_sigma_share23.read(self.num_bytes),sys.byteorder)
                        sigma_share12 = int.from_bytes(file_sigma_share12.read(self.num_bytes),sys.byteorder)
                        y_i = (y_i + beta_share23 * sigma_share23 + beta_share12 * sigma_share23 + beta_share23 * sigma_share12) & self.mask
                    else:
                        beta_share13 = int.from_bytes(file_beta_share13.read(self.num_bytes),sys.byteorder)
                        beta_share23 = int.from_bytes(file_beta_share23.read(self.num_bytes),sys.byteorder)
                        sigma_share13 = int.from_bytes(file_sigma_share13.read(self.num_bytes),sys.byteorder)
                        sigma_share23 = int.from_bytes(file_sigma_share23.read(self.num_bytes),sys.byteorder)
                        y_i = (y_i + beta_share13 * sigma_share13 + beta_share13 * sigma_share23 + beta_share23 * sigma_share13) & self.mask
                    file_epsilon_shares.write(y_i.to_bytes(self.num_bytes, sys.byteorder))

        self.logger.info('compute 3-out-of-3 additive sharings of epsilons via multiplication protocol done.')
        # close files
        if self.id == 1 or self.id == 2:
            file_beta_share12.close()
            file_sigma_share12.close()
        if self.id == 1 or self.id == 3:
            file_beta_share13.close()
            file_sigma_share13.close()
        if self.id == 2 or self.id == 3:
            file_beta_share23.close()
            file_sigma_share23.close()
        

        file_epsilon_shares.close()
        if self.id == 1:
            file_epsilon_shares = open(self.filename_epsilon_shares1,'r+b')
        else:
            file_epsilon_shares = open(self.filename_epsilon_shares2,'r+b')
        self.logger.info('sending the 3-out-of-3 additive shares to convert them to replicated sharings...')
        socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.id == 1:
            s2_address = ('localhost',self.peers['2'])
            socket_obj.connect(s2_address)
            request = "SERVER-1-MULTEPSILON"
            socket_obj.send(request.encode())
            for i in range(self.num_clients):
                for j in range(self.data_dimension):
                    for k in range(self.ring_size):
                        socket_obj.send(file_epsilon_shares.read(self.num_bytes))
        elif self.id == 2:
            s3_address = ('localhost',self.peers['3'])
            # socket_obj.connect(s3_address)
            while True:
                try:
                    self.logger.info('connecting to server 3 to send it 3-out-of-3 additive shares...')
                    socket_obj.connect(s3_address)
                    self.logger.info('successfully connect to server 3.')
                    break
                except ConnectionRefusedError as e:
                    self.logger.info("connection refused: %s",e)
                    self.logger.info("retrying in 3 seconds...")
                    time.sleep(3)  # Wait before retrying
                except Exception as e:
                    self.logger.warning("an unexpected error occurred: %s",e)
                    self.logger.info("retrying in 3 seconds...")
                    time.sleep(3)  # Wait before retrying            
            request = "SERVER-2-MULTEPSILON"
            socket_obj.send(request.encode())
            for i in range(self.num_clients):
                for j in range(self.data_dimension):
                    for k in range(self.ring_size):
                        socket_obj.send(file_epsilon_shares.read(self.num_bytes))
        else:
            s1_address = ('localhost',self.peers['1'])                    
            socket_obj.connect(s1_address)
            request = "SERVER-3-MULTEPSILON"
            socket_obj.send(request.encode())
            for i in range(self.num_clients):
                for j in range(self.data_dimension):
                    for k in range(self.ring_size):
                        socket_obj.send(file_epsilon_shares.read(self.num_bytes))
        
        file_epsilon_shares.close()
        self.logger.info('send the 3-out-of-3 additive shares to convert them to replicated sharings done.')
        self.is_multiplication_done = True
        
class ThreadedRequestHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.logger = logging.getLogger('Server '+ str(server.id) + ' - Request Handler')
        socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

    def setup(self):
        # Set a longer timeout or disable it
        # self.request.settimeout(10)  # Set a timeout of 10 seconds (increase this if necessary)
        # Alternatively, disable timeout:
        self.request.settimeout(None)
        
    def handle(self):
        self.logger.info("receive request from: %s", str(self.client_address))
        request = recv_exactly(self.request,20)

        if request.decode() == 'CLIENT-DATAUPLOADING': 
            self.logger.info("received request: CLIENT-DATAUPLOADING")
            # receive client id 
            client_id = recv_exactly(self.request,4)
            client_id = client_id.decode()
            self.logger.info('received client id: %s',client_id)
            response = 'check'
            self.request.send(response.encode())
            # codes to receive client data
            # receive number of shares
            bytes_num_shares = recv_exactly(self.request,3)
            num_shares = int.from_bytes(bytes_num_shares, sys.byteorder)
            self.logger.debug('received number of shares: %s',num_shares)
            self.server.client_data[client_id] = []
            self.server.shares[client_id] = []
            # receive ring size 
            bytes_ring_size = recv_exactly(self.request,1)
            self.server.ring_size = int.from_bytes(bytes_ring_size, sys.byteorder)
            # compute the num_bytes 
            self.server.num_bytes = int(self.server.ring_size / 8)
            # compute the mask 
            self.server.mask = pow(2, self.server.ring_size) - 1
            self.logger.debug('received ring size: %s',self.server.ring_size)
            self.logger.debug('number of bytes: %s',self.server.num_bytes)
            if self.server.id == 1:
                # receive data dimension 
                bytes_data_dimension = recv_exactly(self.request,3)
                self.server.data_dimension = int.from_bytes(bytes_data_dimension, sys.byteorder)
                self.logger.debug('received data dimension: %s',self.server.data_dimension)
                # receive actual client data 
                for i in range(num_shares):
                    bytes_data_i = recv_exactly(self.request,self.server.num_bytes)
                    self.server.client_data[client_id].append(int.from_bytes(bytes_data_i, sys.byteorder))
                    # self.logger.debug('client: %s, received share %s: %s',client_id,i+1,self.server.client_data[client_id][i])
                start = time.perf_counter()
                # recover shares from received seeds
                s_0 = self.server.client_data[client_id][0]
                s_1 = self.server.client_data[client_id][1]
                for i in range(self.server.data_dimension):
                    random.seed(s_0)
                    s_0 += 1
                    x_i_12 = random.randint(0, pow(2, self.server.ring_size)-1)
                    x_i_12 = bitarray(bin(x_i_12)[2:][::-1])
                    assert len(x_i_12) <= self.server.ring_size 
                    if len(x_i_12) < self.server.ring_size:
                        x_i_12.extend('0' * (self.server.ring_size - len(x_i_12)))
                    random.seed(s_1)
                    s_1 += 1
                    x_i_13 = random.randint(0, pow(2, self.server.ring_size)-1)
                    x_i_13 = bitarray(bin(x_i_13)[2:][::-1])
                    assert len(x_i_13) <= self.server.ring_size
                    if len(x_i_13) < self.server.ring_size:
                        x_i_13.extend('0' * (self.server.ring_size - len(x_i_13)))                        
                    self.server.shares[client_id].append((x_i_12,x_i_13))
                    # self.logger.debug('client: %s, dimension: %s, share: %s',client_id,i+1,self.server.shares[client_id][i])
                end = time.perf_counter()
                self.server.running_time['share_recovery'] += (end - start)
            else:
                self.server.data_dimension = num_shares - 1
                self.logger.debug('received data dimension: %s',self.server.data_dimension)
                # receive the seed
                bytes_seed = recv_exactly(self.request,self.server.num_bytes)
                self.server.client_data[client_id].append(int.from_bytes(bytes_seed, sys.byteorder))
                # self.logger.debug('client: %s, received seed: %s',client_id,self.server.client_data[client_id][0])
                # receive shares 
                seed = int.from_bytes(bytes_seed, sys.byteorder)
                start = time.perf_counter()
                for i in range(self.server.data_dimension):
                    bytes = recv_exactly(self.request,self.server.num_bytes)
                    shares_dimension_i = bitarray()
                    # recover bitarray from received bytes
                    shares_dimension_i.frombytes(bytes)
                    # self.logger.debug('client: %s, received share of dimension %s: %s',client_id,i+1,shares_dimension_i)
                    self.server.client_data[client_id].append(shares_dimension_i)
                    if self.server.id == 2: # the seed is s_0
                        random.seed(seed)
                        seed += 1
                        x_i_12 = random.randint(0, pow(2, self.server.ring_size)-1)
                        x_i_12 = bitarray(bin(x_i_12)[2:][::-1])
                        assert len(x_i_12) <= self.server.ring_size 
                        if len(x_i_12) < self.server.ring_size:
                            x_i_12.extend('0' * (self.server.ring_size - len(x_i_12)))
                        self.server.shares[client_id].append((x_i_12,shares_dimension_i))
                    else: # the seed is s_1
                        random.seed(seed)
                        seed += 1
                        x_i_13 = random.randint(0, pow(2, self.server.ring_size)-1)
                        x_i_13 = bitarray(bin(x_i_13)[2:][::-1])
                        assert len(x_i_13) <= self.server.ring_size
                        if len(x_i_13) < self.server.ring_size:
                            x_i_13.extend('0' * (self.server.ring_size - len(x_i_13)))                        
                        self.server.shares[client_id].append((shares_dimension_i,x_i_13))
                    # self.logger.debug('client: %s, dimension: %s, share: %s',client_id,i+1,self.server.shares[client_id][i])
                end = time.perf_counter()
                self.server.running_time['share_recovery'] += (end - start)
            # receive shares of the l2 norm bound 
            if self.server.num_clients_data_received == 0:
                for i in range(2):
                    share = int.from_bytes(recv_exactly(self.request,self.server.num_bytes), sys.byteorder)
                    self.server.share_mu2[i] = share

                # self.logger.debug('received share of l2 norm bound: %s',self.server.share_mu2)

            self.server.num_clients_data_received += 1
            self.logger.debug("num_clients:%s, num_clients_data_received: %s",self.server.num_clients,self.server.num_clients_data_received)
            if self.server.num_clients_data_received == self.server.num_clients:
                self.logger.info("receive client data done.")

                # when the uploading is done, compute the view of received shares for batch check 
                self.logger.info('computing the view of inputs...')
                str_send = bitarray()
                str_comp = bitarray()
                for client_id in self.server.shares.keys():
                    for j in range(self.server.data_dimension):
                        if self.server.id == 1:
                            str_send.extend(self.server.shares[client_id][j][0])
                            str_comp.extend(self.server.shares[client_id][j][1])
                        else:
                            str_send.extend(self.server.shares[client_id][j][1])
                            str_comp.extend(self.server.shares[client_id][j][0])
                hash_obj = hashes.Hash(hashes.SHA256())
                hash_obj.update(str_send.tobytes())
                hash_send = hash_obj.finalize()
                self.server.views_to_send['inputs'] = hash_send
                hash_obj = hashes.Hash(hashes.SHA256())
                hash_obj.update(str_comp.tobytes())
                hash_comp = hash_obj.finalize()
                self.server.views_to_comp['inputs'] = hash_comp

                # self.logger.debug('view to compare:%s',self.server.views_to_comp['inputs'])
                # self.logger.debug('view to send:%s',self.server.views_to_send['inputs'])

                self.server.is_uploading_done = True

                # set filenames
                if self.server.id == 1:
                    self.server.filename_betas = './randomness2/'+'server1'+'_betas'+'_clients'+str(self.server.num_clients)+'_dimension'+str(self.server.data_dimension)+'_ring'+str(self.server.ring_size)+'.bin'
                    self.server.filename_beta_shares12 = './randomness2/'+'server1'+'_beta_shares12'+'_clients'+str(self.server.num_clients)+'_dimension'+str(self.server.data_dimension)+'_ring'+str(self.server.ring_size)+'.bin'
                    self.server.filename_beta_shares13 = './randomness2/'+'server1'+'_beta_shares13'+'_clients'+str(self.server.num_clients)+'_dimension'+str(self.server.data_dimension)+'_ring'+str(self.server.ring_size)+'.bin'
                    self.server.filename_sigma_shares12 = './randomness2/'+'server1'+'_sigma_shares12'+'_clients'+str(self.server.num_clients)+'_dimension'+str(self.server.data_dimension)+'_ring'+str(self.server.ring_size)+'.bin'
                    self.server.filename_sigma_shares13 = './randomness2/'+'server1'+'_sigma_shares13'+'_clients'+str(self.server.num_clients)+'_dimension'+str(self.server.data_dimension)+'_ring'+str(self.server.ring_size)+'.bin'
                else:
                    self.server.filename_alphas = './randomness2/'+'server'+str(self.server.id)+'_alphas'+'_clients'+str(self.server.num_clients)+'_dimension'+str(self.server.data_dimension)+'_ring'+str(self.server.ring_size)+'.bin'
                    if self.server.id == 2:
                        self.server.filename_beta_shares12 = './randomness2/'+'server2'+'_beta_shares12'+'_clients'+str(self.server.num_clients)+'_dimension'+str(self.server.data_dimension)+'_ring'+str(self.server.ring_size)+'.bin'
                        self.server.filename_beta_shares23 = './randomness2/'+'server2'+'_beta_shares23'+'_clients'+str(self.server.num_clients)+'_dimension'+str(self.server.data_dimension)+'_ring'+str(self.server.ring_size)+'.bin'
                        self.server.filename_sigma_shares12 = './randomness2/'+'server2'+'_sigma_shares12'+'_clients'+str(self.server.num_clients)+'_dimension'+str(self.server.data_dimension)+'_ring'+str(self.server.ring_size)+'.bin'
                        self.server.filename_sigma_shares23 = './randomness2/'+'server2'+'_sigma_shares23'+'_clients'+str(self.server.num_clients)+'_dimension'+str(self.server.data_dimension)+'_ring'+str(self.server.ring_size)+'.bin'
                    else:
                        self.server.filename_beta_shares23 = './randomness2/'+'server3'+'_beta_shares23'+'_clients'+str(self.server.num_clients)+'_dimension'+str(self.server.data_dimension)+'_ring'+str(self.server.ring_size)+'.bin'
                        self.server.filename_beta_shares13 = './randomness2/'+'server3'+'_beta_shares13'+'_clients'+ str(self.server.num_clients)+'_dimension'+str(self.server.data_dimension)+'_ring'+str(self.server.ring_size)+'.bin'
                        self.server.filename_sigma_shares23 = './randomness2/'+'server3'+'_sigma_shares23'+'_clients'+str(self.server.num_clients)+'_dimension'+str(self.server.data_dimension)+'_ring'+str(self.server.ring_size)+'.bin'
                        self.server.filename_sigma_shares13 = './randomness2/'+'server3'+'_sigma_shares13'+'_clients'+str(self.server.num_clients)+'_dimension'+str(self.server.data_dimension)+'_ring'+str(self.server.ring_size)+'.bin'
                self.server.filename_epsilon_shares1 = './randomness2/'+'server'+str(self.server.id)+'_epsilons1'+'_clients'+str(self.server.num_clients)+'_dimension'+str(self.server.data_dimension)+'_ring'+str(self.server.ring_size)+'.bin'
                self.server.filename_epsilon_shares2 = './randomness2/'+'server'+str(self.server.id)+'_epsilons2'+'_clients'+str(self.server.num_clients)+'_dimension'+str(self.server.data_dimension)+'_ring'+str(self.server.ring_size)+'.bin'
        # Server 2 requests for shakehanding
        # so this is Server 1, it sends view of inputs to Server 2
        elif request.decode() == 'SERVER-2-SHAKEHAND--': 
            self.logger.info("received request: SERVER-2-SHAKEHAND--")
            response = "check"
            self.request.send(response.encode())
            self.logger.info('shakehand with peer server 2 done.')
            # start to batch-check the inputs 
            request = "SERVER-1-BATCHCHECK-"
            self.request.send(request.encode())
            while(self.server.is_uploading_done == False): pass
            self.request.send(self.server.views_to_send['inputs'])

        # Server 3 requests for shakehanding
        # so this is Server 1 or Server 2
        elif request.decode() == 'SERVER-3-SHAKEHAND--': 
            self.logger.info("received request: SERVER-3-SHAKEHAND--")
            response = "check"
            self.request.send(response.encode())
            self.logger.info('shakehand with peer server 3 done.')
            # this is Server 2
            # send request for batch-check to server 3
            if self.server.id == 2: 
                request = "SERVER-2-BATCHCHECK-"
                self.request.send(request.encode())
                # Server 2 sends view of inputs to Server 3
                while(self.server.is_uploading_done == False): pass
                self.request.send(self.server.views_to_send['inputs'])
            # this is Serer 1
            else:
                request = recv_exactly(self.request,20)
                assert request.decode() == "SERVER-3-BATCHCHECK-"
                self.server.view_received = recv_exactly(self.request,32)
                # self.logger.debug('view received:%s',self.server.view_received)

                self.server.is_receive_view_of_inputs_done = True

        # Server 1 sends \zetas to server 2 and server 3
        # so this is server 2 or server 3
        # elif request.decode() == 'SERVER-1-SENDZETAS--':
        #     self.logger.info('received request: SERVER-1-SENDZETAS--')
        #     self.logger.info('receiving zetas, computing gammas and deltas...')
        #     # receive zetas, then compute gammas and deltas
        #     file_alphas = open(self.server.filename_alphas,'r+b')
        #     for i in range(self.server.num_clients):
        #         client_id = recv_exactly(self.request,4).decode()
        #         self.server.gammas[client_id] = []
        #         self.server.deltas[client_id] = []
        #         for j in range(self.server.data_dimension):
        #             zeta = bitarray()
        #             alpha = bitarray()
        #             zeta.frombytes(recv_exactly(self.request,self.server.num_bytes))
        #             # self.logger.debug('dimension: %s, received zeta: %s',j+1, zeta)
        #             alpha.frombytes(file_alphas.read(self.server.num_bytes))
        #             # self.logger.debug('dimension: %s, used alpha: %s',j+1,alpha)
        #             if self.server.id == 2:
        #                 gamma = self.server.shares[client_id][j][1] ^ zeta
        #             else:
        #                 gamma = self.server.shares[client_id][j][0] ^ zeta
        #             delta = alpha ^ gamma
        #             self.server.gammas[client_id].append(gamma)
        #             self.server.deltas[client_id].append(delta)

        #     file_alphas.close()
        #     if self.server.id == 2:
        #         self.server.is_receive_zetas_done = True 
        #     else:
        #         self.server.is_ready_for_share_conversion_phase2 = True
        #     self.logger.info('receive zetas from server 1 done, compute gammas and deltas done.')

        elif request.decode() == 'SERVER-1-SENDZETAS--':
            self.logger.info('received request: SERVER-1-SENDZETAS--')
            self.logger.info('receiving zetas, computing gammas and deltas...')

            start = time.perf_counter()
            # Open file for alpha values
            with open(self.server.filename_alphas, 'r+b') as file_alphas:
                chunk_size = 1000  # Process dimensions in batches
                for i in range(self.server.num_clients):
                    client_id = recv_exactly(self.request, 4).decode()
                    self.server.gammas[client_id] = []
                    self.server.deltas[client_id] = []

                    # Process data_dimension in chunks
                    dimension_index = 0
                    for start_idx in range(0, self.server.data_dimension, chunk_size):
                        end_idx = min(start_idx + chunk_size, self.server.data_dimension)

                        # Receive all zeta values for this chunk in one go
                        zeta_bytes = recv_exactly(self.request, self.server.num_bytes * (end_idx - start_idx))
                        zeta_chunk = bitarray()
                        zeta_chunk.frombytes(zeta_bytes)

                        # Read all alpha values for this chunk in one go
                        alpha_chunk = bitarray()
                        alpha_chunk.frombytes(file_alphas.read(self.server.num_bytes * (end_idx - start_idx)))

                        # Process each dimension in the chunk
                        for i in range(start_idx, end_idx):
                            zeta = zeta_chunk[(i - start_idx) * self.server.num_bytes * 8 : (i - start_idx + 1) * self.server.num_bytes * 8]
                            alpha = alpha_chunk[(i - start_idx) * self.server.num_bytes * 8 : (i - start_idx + 1) * self.server.num_bytes * 8]

                            # Compute gamma and delta
                            if self.server.id == 2:
                                gamma = self.server.shares[client_id][dimension_index][1] ^ zeta
                            else:
                                gamma = self.server.shares[client_id][dimension_index][0] ^ zeta
                            delta = alpha ^ gamma
                            dimension_index += 1
                            # Store gamma and delta
                            self.server.gammas[client_id].append(gamma)
                            self.server.deltas[client_id].append(delta)
            end = time.perf_counter()
            self.server.running_time['share_conversion_phase1'] = (end - start)

            # Set appropriate flags based on the server ID
            if self.server.id == 2:
                self.server.is_receive_zetas_done = True
            else:
                self.server.is_ready_for_share_conversion_phase2 = True

            self.logger.info('receive zetas from server 1 done, compute gammas and deltas done.')

        # Server 2 sends etas to server 1, so this is server 1 
        elif request.decode() == 'SERVER-2-SENDETAS---':
            self.logger.info('received request: SERVER-2-SENDETAS---')
            start = time.perf_counter()
            for i in range(self.server.num_clients):
                client_id = recv_exactly(self.request,4).decode()
                self.server.deltas[client_id] = []
                for j in range(self.server.data_dimension):
                    eta = bitarray()
                    eta.frombytes(recv_exactly(self.request,self.server.num_bytes))
                    # self.logger.debug('client: %s, dimension: %s, used eta: %s',client_id,j+1,eta)
                    # here compute server computes delta=eta ^ [x]_12 ^ [x]_13
                    self.server.deltas[client_id].append(eta ^ self.server.shares[client_id][j][0] ^ self.server.shares[client_id][j][1])
            end = time.perf_counter()
            self.server.running_time['share_conversion_phase1'] += (end - start)
            self.server.is_share_conversion_phase1_done = True 

        # Server 2 notifies server 1 that it is ready for share conversion 
        # so this is server 1
        elif request.decode() == 'SERVER-2-READYCONVER':
            self.logger.info('received request: SERVER-2-READYCONVER')
            response = 'check'
            self.request.send(response.encode())

            self.server.is_server2_ready_for_share_conversion_phase1 = True 

        # Server 3 notifies server 1 that it is ready for share conversion 
        # so this is server 1
        elif request.decode() == 'SERVER-3-READYCONVER':
            self.logger.info('received request: SERVER-3-READYCONVER')
            response = 'check'
            self.request.send(response.encode())

            self.server.is_server3_ready_for_share_conversion_phase1 = True 

        elif request.decode() == 'SERVER-1-MULTEPSILON': # Server 1 sends 3-out-of-3 additive share to Server 2
            self.logger.info('received request: SERVER-1-MULTEPSILON')
            file_epsilon_shares = open(self.server.filename_epsilon_shares1,'w+b')
            for i in range(self.server.num_clients):
                for j in range(self.server.data_dimension):
                    for k in range(self.server.ring_size):
                        file_epsilon_shares.write(recv_exactly(self.request,self.server.num_bytes))
            file_epsilon_shares.close()
            self.server.is_receive_multiplication_share_done = True
            self.logger.info('receive 3-out-of-3 additive shares done.')

        elif request.decode() == 'SERVER-2-MULTEPSILON': # Server 2 sends 3-out-of-3 additive share to Server 3
            self.logger.info('received request: SERVER-2-MULTEPSILON')
            file_epsilon_shares = open(self.server.filename_epsilon_shares1,'w+b')
            for i in range(self.server.num_clients):
                for j in range(self.server.data_dimension):
                    for k in range(self.server.ring_size):
                        file_epsilon_shares.write(recv_exactly(self.request,self.server.num_bytes))
            file_epsilon_shares.close()
            self.server.is_receive_multiplication_share_done = True
            self.logger.info('receive 3-out-of-3 additive shares done.')

        elif request.decode() == 'SERVER-3-MULTEPSILON': # Server 3 sends 3-out-of-3 additive share to Server 1
            self.logger.info('received request: SERVER-3-MULTEPSILON')
            file_epsilon_shares = open(self.server.filename_epsilon_shares2,'w+b')
            for i in range(self.server.num_clients):
                for j in range(self.server.data_dimension):
                    for k in range(self.server.ring_size):
                        file_epsilon_shares.write(recv_exactly(self.request,self.server.num_bytes))
            file_epsilon_shares.close()
            self.server.is_receive_multiplication_share_done = True
            self.logger.info('receive 3-out-of-3 additive shares done.')

        elif request.decode() == 'SERVER-1-3OF3SHARES-' or \
            request.decode() == 'SERVER-2-3OF3SHARES-' or \
            request.decode() == 'SERVER-3-3OF3SHARES-': # Servers send shares of l2 norm 
            self.logger.info('received request: %s',request.decode())
            start = time.perf_counter()
            for i in range(self.server.num_clients):
                client_id = recv_exactly(self.request,4).decode()
                share = int.from_bytes(recv_exactly(self.request,self.server.num_bytes), sys.byteorder)
                self.server.received_shares_of_l2_norm[client_id] = share
            end = time.perf_counter()
            self.server.running_time['l2_norm_computation'] += (end - start)
            self.server.is_receive_l2norm_share_done = True
              
        # Servers send partial share of differences to open them 
        elif request.decode() == 'SERVER-1-OPENDIFFERE' or \
             request.decode() == 'SERVER-2-OPENDIFFERE' or \
             request.decode() == 'SERVER-3-OPENDIFFERE':
            self.logger.info('receive request: %s',request.decode())
            for i in range(self.server.num_clients):
                client_id = recv_exactly(self.request,4).decode() 
                share = int.from_bytes(recv_exactly(self.request,self.server.num_bytes), sys.byteorder)
                self.server.received_shares_of_differences[client_id] = share
            self.server.is_receive_shares_of_differences_done = True
        
        # Servers send the view of the differences 
        elif request.decode() == 'SERVER-1-VIEWDIFFERE' or \
             request.decode() == 'SERVER-2-VIEWDIFFERE' or \
             request.decode() == 'SERVER-3-VIEWDIFFERE':
            self.logger.info('receive request: %s',request.decode())
            self.server.received_view_of_difference = self.request.recv(32)
            self.server.is_receive_view_of_difference_done = True
                
        # Server 1 sends [\beta]_{13} to Server 3 for share conversion 
        elif request.decode() == 'SERVER-1-BETASHARES-':
            file_beta_shares13 = open(self.server.filename_beta_shares13, 'w+b')
            self.logger.info('receive request: SERVER-1-BETASHARES-')
            self.logger.info('combing share of beta...')
            for i in range(self.server.num_clients):
                for j in range(self.server.data_dimension):
                    for k in range(self.server.ring_size):
                        file_beta_shares13.write(recv_exactly(self.request,self.server.num_bytes))
            self.logger.info('combine share of beta done.')
            file_beta_shares13.close()
            self.server.is_receive_share_beta13_done = True
        else:
            self.logger.error("unknown request.")

if __name__ == '__main__':
    import sys 
    import getopt 
    try:
        opts, args = getopt.getopt(sys.argv[1:],"i:p:n:o:g:d:u:",["id=","port=","num_clients=","offline=","generate=","dimension=","upperbound="])
    except getopt.GetoptError as e:
        print(e.msg)
        print(e.opt)
        sys.exit(2)

    id, port, num_clients, offline, generate, dimension, upperbound = 0, 0, 0, 0, 0, 0, 0
    for opt, arg in opts:
        if opt in ("-i","--id"):
            id = int(arg)
        elif opt in ("-p","--port"):
            port = int(arg)
        elif opt in ("-n","--num_clients"):
            num_clients = int(arg)
        elif opt in ("-o","--offline"):
            offline = int(arg)
        elif opt in ("-g","--generate"):
            generate = int(arg)
        elif opt in ("-d","--dimension"):
            dimension = int(arg)
        elif opt in ("-u","--upperbound"):
            upperbound = int(arg)

    if generate > 0:
        assert (offline == 0) and (dimension > 0) and (upperbound > 0)
    
    address_server = ('localhost', port) 
    server = ThreadedServer(id=id, num_clients=num_clients,offline=offline,generate=generate,dimension=dimension,upperbound=upperbound, 
                            address=address_server, handler_class=ThreadedRequestHandler)
    server.serve_forever()



