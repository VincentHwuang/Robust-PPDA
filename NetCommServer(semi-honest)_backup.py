import sys
import time
import math 
import torch 
import random 
import logging
import coloredlogs
import socket 
import threading
import socketserver
import numpy as np
from bitarray import bitarray
from typing import Tuple, List, Dict, Union
from Utility import extract_boolean_shares, \
    setup, int_to_twos_complement, int_from_twos_complement
from cryptography.hazmat.primitives import hashes, hmac

coloredlogs.install(level='DEBUG')
logging.basicConfig(level=logging.DEBUG,
                    format='%(name)s: %(message)s',
                    )

REQUESTS = ("CLIENT-DATAUPLOADING","SERVER-2-SHAKEHAND--","SERVER-3-SHAKEHAND--",
            "SERVER-1-BATCHCHECK-","SERVER-2-BATCHCHECK-","SERVER-3-BATCHCHECK-", 
            "SERVER-1-CONVERSION-","SERVER-2-CONVERSION-","SERVER-3-CONVERSION-",
            "SERVER-1-NORMCOMPUT-","SERVER-2-NORMCOMPUT-","SERVER-3-NORMCOMPUT-",
            "SERVER-1-MULTEPSILON","SERVER-2-MULTEPSILON","SERVER-3-MULTEPSILON",
            "SERVER-1-MULTIBATCH2","SERVER-2-MULTIBATCH2","SERVER-3-MULTIBATCH2",
            "SERVER-1-OPENSHARES-","SERVER-2-OPENSHARES-","SERVER-3-OPENSHARES-",
            "SERVER-1-CHECKVIEWS-","SERVER-2-CHECKVIEWS-","SERVER-3-CHECKVIEWS-",
            "SERVER-1-OPENV------","SERVER-2-OPENV------","SERVER-3-OPENV------",
            "SERVER-1-CHECKVIEWV-","SERVER-2-CHECKVIEWV-","SERVER-3-CHECKVIEWV-",
            "SERVER-1-OPENDIFFERE","SERVER-2-OPENDIFFERE","SERVER-3-OPENDIFFERE",
            "SERVER-1-VIEWDIFFERE","SERVER-2-VIEWDIFFERE","SERVER-3-VIEWDIFFERE",
            "SERVER-1-BETASHARES-")

# component-wise bounding parameter L 
L = 90
# setup materials
setup_materials = {'keys': [(b'\xf7\xb0\x91\xc8\xdf\x81\r\xd1', b'\x83<G\xd8?\rG}', b'\x11\xab\x14sO\\\x17X'),(b'\xf7\xb0\x91\xc8\xdf\x81\r\xd1', b'\xc2\xa7\xe1\xb2,\x08\xe58', b'\x11\xab\x14sO\\\x17X'),(b'\xc2\xa7\xe1\xb2,\x08\xe58', b'\x83<G\xd8?\rG}', b'\x11\xab\x14sO\\\x17X')],
                   'PRF_counters': [[14946496669844502460, 12922771947244445395, 12301499682450725286], [14946496669844502460, 3500725044436648833, 12301499682450725286], [3500725044436648833, 12922771947244445395, 12301499682450725286]]}

# generate two random values to test the multiplication protocol 
# x = 150
# y = 4
# x_12,x_13,x_23 = 100,45,5
# y_12,y_13,y_23 = 1,1,2

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, id, num_clients, offline, address, handler_class):
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
        self.ring_size = 0
        self.num_bytes = 0
        self.mask = 0
        self.client_data = {}
        self.shares = {}
        self.views_to_send = {}
        self.views_to_comp = {}
        self.view_received = b''
        self.data_dimension = 0
        self.num_clients_data_received = 0
        self.shares_of_l2_norm = {}
        self.received_shares_of_l2_norm = {}
        self.yis_in_multiplication_protocol = {}
        self.received_yis_in_multiplication_protocol = {}
        self.alphas = {} # used by Server 2 and Server 3
        self.betas = {}  # used by Server 1
        self.shares_of_sigmas_for_share_conversion = {}
        self.shares_of_betas_for_share_conversion = {}
        self.received_beta13_for_share_conversion = {} # used by Server 3 
        self.is_uploading_done = False
        self.is_receive_view_of_inputs_done = False
        self.is_input_batchcheck_done = False
        self.is_handshaking_in_progress = False
        self.is_component_wise_bounding_in_progress = False
        self.is_component_wise_bounding_done = False
        self.is_correlated_tuples_generation_in_progress = False
        self.is_local_computation_of_correlated_tuples_generation_done = False
        self.is_multiplication_of_correlated_tuples_generation_in_progress = False
        self.is_share_conversion_in_progress = False
        self.is_share_transmission_for_conversion_done = False
        self.is_multiplication_in_progress = False
        self.is_norm_share_computation_done = False
        self.is_multiplication_done = False
        self.is_receive_multiplication_share_done = False
        self.is_receive_l2norm_share_done = False
        self.is_receive_share_beta13_done = False # used by Server 3
        self.final_converted_arithmetic_shares = {}
        self.share_mu2 = [0,0]
        self.zs = {}
        self.shares_of_arithmetic_z_shares = {}
        self.is_receive_boolean_share_done = False
        self.is_receive_boolean_share_hash_done = False
        self.received_hash_of_z_shares = b''
        self.received_shares_of_differences = {}
        self.is_receive_shares_of_differences_done = False
        self.is_receive_view_of_differences_done = False
        self.differences = {}
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
            if self.is_uploading_done == True and self.id == 2 and self.is_handshaking_in_progress == False:
                self.logger.info('send shakehanding requests to peers...')
                port_server1, _ = self.peers.values()
                thread = threading.Thread(target=self.handshaking_and_batchchecking, args=(port_server1,))
                self.is_handshaking_in_progress = True
                self.logger.info('shakehand with peer server 1.')
                thread.start()

            if self.is_uploading_done == True and self.id == 3 and self.is_handshaking_in_progress == False:
                self.logger.info('send shakehanding requests to peers...')
                port_server1, port_server2 = self.peers.values()
                thread1 = threading.Thread(target=self.handshaking_and_batchchecking, args=(port_server1,1))
                thread2 = threading.Thread(target=self.handshaking_and_batchchecking, args=(port_server2,2))
                self.is_handshaking_in_progress = True
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
                self.is_input_batchcheck_done = True

            if self.is_input_batchcheck_done == True and self.is_component_wise_bounding_in_progress == False:
                self.is_component_wise_bounding_in_progress = True
                self.logger.info('enter the second phase: norm-bounding based selection...')
                self.logger.info('start to enforce component wise bounding...')
                thread = threading.Thread(target=self.component_wise_bounding, args=())
                thread.start()

            if self.is_component_wise_bounding_done == True and self.is_correlated_tuples_generation_in_progress == False:
                self.is_correlated_tuples_generation_in_progress = True
                if self.offline == 0:
                    self.logger.info('start to generate correlated random tuples for share conversion...')
                    thread = threading.Thread(target=self.generate_correlated_tuples, args=())
                    thread.start()
                else:
                    self.logger.info('use precomputed correlated random tuples for share conversion.')

            if self.is_local_computation_of_correlated_tuples_generation_done == True and self.is_multiplication_of_correlated_tuples_generation_in_progress == False:
                if self.id == 3:
                    if self.is_receive_share_beta13_done == True:
                        self.is_multiplication_of_correlated_tuples_generation_in_progress = True
                        self.logger.info('combing share of beta...')
                        assert self.shares_of_betas_for_share_conversion.keys() == self.received_beta13_for_share_conversion.keys()
                        for client_id in self.shares_of_betas_for_share_conversion.keys():
                            assert len(self.shares_of_betas_for_share_conversion[client_id]) == self.data_dimension
                            assert len(self.received_beta13_for_share_conversion[client_id]) == self.data_dimension
                            for i in range(self.data_dimension):
                                assert len(self.shares_of_betas_for_share_conversion[client_id][i]) == self.ring_size
                                assert len(self.received_beta13_for_share_conversion[client_id][i]) == self.ring_size
                                for j in range(self.ring_size):
                                    self.shares_of_betas_for_share_conversion[client_id][i][j][1] = self.received_beta13_for_share_conversion[client_id][i][j]
                        self.logger.info('combine share of beta done.')
                        self.logger.info('computing sharings of epsilons via multiplication protocol...')
                        # prepare shares for multiplication to compute sharings [\epsilon_i]^A
                        # shares = {}
                        # assert self.shares_of_betas_for_share_conversion.keys() == self.shares_of_sigmas_for_share_conversion.keys()
                        # for client_id in self.shares_of_betas_for_share_conversion.keys():
                        #     shares[client_id] = []
                        #     assert len(self.shares_of_betas_for_share_conversion[client_id]) == self.data_dimension
                        #     assert len(self.shares_of_sigmas_for_share_conversion[client_id]) == self.data_dimension
                        #     for i in range(self.data_dimension):
                        #         shares[client_id].append([])
                        #         shares[client_id][i].append(self.shares_of_betas_for_share_conversion[client_id][i])
                        #         shares[client_id][i].append(self.shares_of_sigmas_for_share_conversion[client_id][i])
                        
                        # thread = threading.Thread(target=self.semihonest_multiplication_batch,args=(shares,))
                        # thread.start()

                        thread = threading.Thread(target=self.semihonest_multiplication_batch,args=())
                        thread.start()
                else:
                    self.is_multiplication_of_correlated_tuples_generation_in_progress = True
                    self.logger.info('computing 3-out-of-3 additive sharings of epsilons via multiplication protocol...')
                    # prepare shares for multiplication to compute sharings [\epsilon_i]^A
                    # shares = {}
                    # assert self.shares_of_betas_for_share_conversion.keys() == self.shares_of_sigmas_for_share_conversion.keys()
                    # for client_id in self.shares_of_betas_for_share_conversion.keys():
                    #     shares[client_id] = []
                    #     assert len(self.shares_of_betas_for_share_conversion[client_id]) == self.data_dimension
                    #     assert len(self.shares_of_sigmas_for_share_conversion[client_id]) == self.data_dimension
                    #     for i in range(self.data_dimension):
                    #         shares[client_id].append([])
                    #         shares[client_id][i].append(self.shares_of_betas_for_share_conversion[client_id][i])
                    #         shares[client_id][i].append(self.shares_of_sigmas_for_share_conversion[client_id][i])
                    
                    # thread = threading.Thread(target=self.semihonest_multiplication_batch,args=(shares,))
                    # thread.start()

                    thread = threading.Thread(target=self.semihonest_multiplication_batch,args=())
                    thread.start()

            if self.is_multiplication_done == True and self.is_receive_multiplication_share_done == True:
                self.is_multiplication_done = False 
                self.logger.info('combing shares of epsilons...')
                # write the results to a file 
                filename = 'server'+str(self.id)+'_clients'+str(self.num_clients)+'_dimension'+str(self.data_dimension)+'_ring'+str(self.ring_size)+'.bin'
                file = open(filename, 'a+b')
                
                assert self.yis_in_multiplication_protocol.keys() == self.received_yis_in_multiplication_protocol.keys()
                for client_id in self.yis_in_multiplication_protocol.keys():
                    assert len(self.yis_in_multiplication_protocol[client_id]) == len(self.received_yis_in_multiplication_protocol[client_id])
                    assert len(self.yis_in_multiplication_protocol[client_id]) == self.data_dimension
                    for i in range(self.data_dimension):
                        assert len(self.yis_in_multiplication_protocol[client_id][i]) == len(self.received_yis_in_multiplication_protocol[client_id][i])
                        assert len(self.yis_in_multiplication_protocol[client_id][i]) == self.ring_size
                        for j in range(self.ring_size):
                            if self.id == 1:
                                # self.yis_in_multiplication_protocol[client_id][i][j][1] = self.received_yis_in_multiplication_protocol[client_id][i][j]
                                file.write(self.yis_in_multiplication_protocol[client_id][i][j].to_bytes(self.num_bytes,sys.byteorder))
                                file.write(self.received_yis_in_multiplication_protocol[client_id][i][j].to_bytes(self.num_bytes,sys.byteorder))
                            else:
                                # self.yis_in_multiplication_protocol[client_id][i][j][0] = self.received_yis_in_multiplication_protocol[client_id][i][j]
                                file.write(self.received_yis_in_multiplication_protocol[client_id][i][j].to_bytes(self.num_bytes, sys.byteorder))
                                file.write(self.yis_in_multiplication_protocol[client_id][i][j].to_bytes(self.num_bytes,sys.byteorder))

                self.logger.info('combine shares of epsilons done.')

                # for client_id in self.yis_in_multiplication_protocol.keys():
                #     for i in range(self.data_dimension):
                #         for j in range(self.ring_size):
                #             file.write(self.yis_in_multiplication_protocol[client_id][i][j][0].to_bytes(self.num_bytes,sys.byteorder))
                #             file.write(self.yis_in_multiplication_protocol[client_id][i][j][1].to_bytes(self.num_bytes,sys.byteorder))
                file.close()

                self.logger.info('generate correlated random tuples for share conversion done.')

                # used for debug 
                for client_id in self.yis_in_multiplication_protocol.keys():
                    for i in range(self.data_dimension):
                            if self.id == 1:
                                self.logger.debug('client: %s, dimension: %s, share0 of epsilons:\n%s\n',client_id,i+1,self.yis_in_multiplication_protocol[client_id][i])
                                self.logger.debug('share1 of epsilons:\n%s\n',client_id,i+1,self.received_yis_in_multiplication_protocol[client_id][i])
                            else:
                                self.logger.debug('client: %s, dimension: %s, share0 of epsilons:\n%s\n',client_id,i+1,self.received_yis_in_multiplication_protocol[client_id][i])
                                self.logger.debug('share1 of epsilons:\n%s\n',client_id,i+1,self.yis_in_multiplication_protocol[client_id][i])
            # if self.is_receive_l2norm_share_done == True:
            #     # enforce l2 norm bounding 
            #     # compute the sharing of difference between the norm and the bound 
            #     self.logger.info('computing shares of difference between the l2 norm and specified bound...')
            #     # self.logger.debug('shares of mu2: %s',self.share_mu2)
            #     for client_id in self.shares_of_l2_norm.keys():
            #         self.zs[client_id] = ((self.shares_of_l2_norm[client_id][0] - self.share_mu2[0]) & self.mask,\
            #                               (self.shares_of_l2_norm[client_id][1] - self.share_mu2[1]) & self.mask) 
            #         # self.logger.debug('shares of l2 norm of client %s: %s',client_id,self.shares_of_l2_norm[client_id])
            #         # self.logger.debug('share of l2 norm of client %s: %s',client_id,self.shares_of_l2_norm[client_id])
            #         # self.logger.debug('share of difference of client %s: %s',client_id,self.zs[client_id])
                    
            #     # open the differences to enforce the norm bounding 
            #     if self.id == 1:
            #         address = ('localhost',self.peers['2'])
            #         request = "SERVER-1-OPENDIFFERE"
            #     elif self.id == 2:
            #         address = ('localhost',self.peers['3'])
            #         request = "SERVER-2-OPENDIFFERE"
            #     else:
            #         address = ('localhost',self.peers['1'])
            #         request = "SERVER-3-OPENDIFFERE"
            #     socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #     socket_obj.connect(address)
            #     socket_obj.send(request.encode())

            #     for client_id in self.zs.keys():
            #         socket_obj.send(client_id.encode())
            #         if self.id == 1:
            #             socket_obj.send(self.zs[client_id][1].to_bytes(self.num_bytes, sys.byteorder))
            #         else:
            #             socket_obj.send(self.zs[client_id][0].to_bytes(self.num_bytes, sys.byteorder))
            
            # if self.is_receive_view_of_differences_done == True:
            #     self.is_receive_view_of_differences_done = False 
            #     self.logger.info('aggregating data of benign clients...')
            #     aggregation = [[0,0] for i in range(self.data_dimension)]
            #     num_clients_involved = 0
            #     for client_id in self.differences.keys():
            #         # self.logger.debug('arithmetic shares of data of client %s:\n%s',client_id,self.final_converted_arithmetic_shares[client_id])
            #         difference = int_from_twos_complement(int_to_twos_complement(self.differences[client_id], self.ring_size), self.ring_size)
            #         self.logger.debug('difference of client %s: %s', client_id,difference)
            #         if difference <= 0:
            #             for i in range(self.data_dimension):
            #                 aggregation[i][0] = (aggregation[i][0] + self.final_converted_arithmetic_shares[client_id][i][0]) & self.mask
            #                 aggregation[i][1] = (aggregation[i][1] + self.final_converted_arithmetic_shares[client_id][i][1]) & self.mask
            #             num_clients_involved += 1
            #     # division 
            #     # aggregation_array = np.array(aggregation, dtype=object)
            #     # aggregation = aggregation_array // num_clients_involved

            #     self.logger.debug('aggregation: %s',aggregation)

            #     # reset all variables
            #     self.ring_size = 0
            #     self.num_bytes = 0
            #     self.mask = 0
            #     self.client_data = {}
            #     self.shares = {}
            #     self.shares_of_beaver_triples_ais = {}
            #     self.shares_of_beaver_triples_cis = {}
            #     self.views_to_send = {}
            #     self.views_to_comp = {}
            #     self.data_dimension = 0
            #     self.num_clients_data_received = 0
            #     self.shares_of_l2_norm = {}
            #     self.received_shares_of_l2_norm = {}
            #     self.yis_in_multiplication_protocol = {}
            #     self.received_yis_in_multiplication_protocol = {}
            #     self.is_uploading_done = False
            #     self.is_input_batchcheck_done = False
            #     self.is_handshaking_in_progress = False
            #     self.is_component_wise_bounding_in_progress = False
            #     self.is_component_wise_bounding_done = False
            #     self.is_share_conversion_in_progress = False
            #     self.is_share_transmission_for_conversion_done = False
            #     self.is_multiplication_in_progress = False
            #     self.is_norm_share_computation_done = False
            #     self.is_multiplication_done = False
            #     self.is_receive_multiplication_share_done = False
            #     self.is_receive_l2norm_share_done = False
            #     self.final_converted_arithmetic_shares = {}
            #     self.share_mu2 = [0,0]
            #     self.zs = {}
            #     self.shares_of_arithmetic_z_shares = {}
            #     self.is_receive_boolean_share_done = False
            #     self.is_receive_boolean_share_hash_done = False
            #     self.received_hash_of_z_shares = b''
            #     self.received_shares_of_differences = {}
            #     self.is_receive_shares_of_differences_done = False
            #     self.differences = {}


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
            response = socket_obj.recv(5)
            if response.decode() == 'check':
                self.logger.info('shakehand with peer done.')
            else:
                self.logger.error('failed to shakehand with peer.')
            # receive the batch-check request from server 1
            response = socket_obj.recv(20)
            assert response.decode() == "SERVER-1-BATCHCHECK-"
            # receive the 32-byte view 
            self.view_received = socket_obj.recv(32)

            self.is_receive_view_of_inputs_done = True

        elif self.id == 3:
            assert peer_id == 1 or peer_id == 2
            request = 'SERVER-3-SHAKEHAND--'
            socket_obj.send(request.encode())
            # receive the response from peer 
            response = socket_obj.recv(5)
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
                request = socket_obj.recv(20).decode()
                assert request == "SERVER-2-BATCHCHECK-"
                self.view_received = socket_obj.recv(32)

                self.is_receive_view_of_inputs_done = True

    def component_wise_bounding(self):
        result = True
        for client_id in self.shares.keys():
            for i in range(self.data_dimension):
                if len(self.shares[client_id][i][0]) <= L and len(self.shares[client_id][i][1]) <= L:
                    pass
                else:
                    result = False
                    self.logger.error('bit length of input boolean shares exceeds the bound!')
        if result == True:
            self.logger.info('component wise bounding: pass.')
        self.is_component_wise_bounding_done = True

    def generate_correlated_tuples(self):
        # write alphas or betas to a file 
        filename = 'server'+str(self.id)+'_clients'+str(self.num_clients)+'_dimension'+str(self.data_dimension)+'_ring'+str(self.ring_size)+'.bin'
        file = open(filename, 'w+b')
        for client_id in self.shares.keys():
            self.shares_of_sigmas_for_share_conversion[client_id] = []
            self.shares_of_betas_for_share_conversion[client_id] = []
            for i in range(self.data_dimension):
                alpha_dimension_i = bitarray()
                beta_dimension_i = bitarray()
                self.shares_of_sigmas_for_share_conversion[client_id].append([])
                self.shares_of_betas_for_share_conversion[client_id].append([])
                for j in range(self.ring_size):
                    if self.id == 1:
                        # S1 randomly selects a bit \beta
                        beta = random.getrandbits(1)
                        beta_dimension_i.append(beta)

                        # S1,S2 jointly generate share [\beta]_{12}
                        ctr12_bytes = self.PRF_counters[0].to_bytes(8, sys.byteorder)
                        hmac_obj = hmac.HMAC(self.keys[0], hashes.SHA256())
                        hmac_obj.update(ctr12_bytes)
                        beta_12 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) 
                        self.PRF_counters[0] += 1

                        # S1,S2,S3 jointly generate share [\beta]_{23}
                        ctrS_bytes = self.PRF_counters[2].to_bytes(8, sys.byteorder)
                        hmac_obj = hmac.HMAC(self.keys[2], hashes.SHA256())
                        hmac_obj.update(ctrS_bytes)
                        beta_23 = int.from_bytes(hmac_obj.finalize(), sys.byteorder)
                        self.PRF_counters[2] += 1

                        # S1 computes share [\beta]_{13}
                        beta_13 = (beta - beta_12 - beta_23) & self.mask

                        # S1 sets its share of alpha to (0,0)
                        self.shares_of_sigmas_for_share_conversion[client_id][i].append([0,0])
                        # S1 sets its share of beta
                        self.shares_of_betas_for_share_conversion[client_id][i].append((beta_12,beta_13))

                    elif self.id == 2:
                        # S2,S3 jointly select bit \alpha
                        ctr23_bytes = self.PRF_counters[1].to_bytes(8, sys.byteorder)
                        hmac_obj = hmac.HMAC(self.keys[1], hashes.SHA256())
                        hmac_obj.update(ctr23_bytes)
                        alpha = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & 1
                        alpha_dimension_i.append(alpha)
                        self.PRF_counters[1] += 1

                        # S2 sets its share of alpha to (0,alpha)
                        self.shares_of_sigmas_for_share_conversion[client_id][i].append([0,alpha])

                        # S1,S2 jointly generate share [\beta]_{12}
                        ctr12_bytes = self.PRF_counters[0].to_bytes(8, sys.byteorder)
                        hmac_obj = hmac.HMAC(self.keys[0], hashes.SHA256())
                        hmac_obj.update(ctr12_bytes)
                        beta_12 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) 
                        self.PRF_counters[0] += 1

                        # S1,S2,S3 jointly generate share [\beta]_{23}
                        ctrS_bytes = self.PRF_counters[2].to_bytes(8, sys.byteorder)
                        hmac_obj = hmac.HMAC(self.keys[2], hashes.SHA256())
                        hmac_obj.update(ctrS_bytes)
                        beta_23 = int.from_bytes(hmac_obj.finalize(), sys.byteorder)
                        self.PRF_counters[2] += 1

                        # S2 sets its share of beta
                        self.shares_of_betas_for_share_conversion[client_id][i].append((beta_12,beta_23))

                    else:
                        # S2,S3 jointly select bit \alpha 
                        ctr23_bytes = self.PRF_counters[0].to_bytes(8, sys.byteorder)
                        hmac_obj = hmac.HMAC(self.keys[0], hashes.SHA256())
                        hmac_obj.update(ctr23_bytes)
                        alpha = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & 1
                        alpha_dimension_i.append(alpha)
                        self.PRF_counters[0] += 1

                        # S3 sets its share of alpha to (alpha,0)
                        self.shares_of_sigmas_for_share_conversion[client_id][i].append([alpha,0])

                        # S1,S2,S3 jointly generate share [\beta]_{23}
                        ctrS_bytes = self.PRF_counters[2].to_bytes(8, sys.byteorder)
                        hmac_obj = hmac.HMAC(self.keys[2], hashes.SHA256())
                        hmac_obj.update(ctrS_bytes)
                        beta_23 = int.from_bytes(hmac_obj.finalize(), sys.byteorder)
                        self.PRF_counters[2] += 1

                        # S3 set its partial share of beta: [\beta]_{23}
                        # it needs to receive [\beta]_{13} from S1
                        self.shares_of_betas_for_share_conversion[client_id][i].append([0,0])
                        self.shares_of_betas_for_share_conversion[client_id][i][j][0] = beta_23

                    # S1,S2,S3 compute [\sigma]= 1-2\cdot[\alpha]
                    self.shares_of_sigmas_for_share_conversion[client_id][i][j][0] = (1 - 2 * self.shares_of_sigmas_for_share_conversion[client_id][i][j][0]) & self.mask
                    self.shares_of_sigmas_for_share_conversion[client_id][i][j][1] = (1 - 2 * self.shares_of_sigmas_for_share_conversion[client_id][i][j][1]) & self.mask
                
                if self.id == 1:
                    file.write(beta_dimension_i.tobytes())
                else:
                    file.write(alpha_dimension_i.tobytes())

        file.close()
        # S1 sends [\beta]_{13} to S3
        if self.id == 1:
            self.logger.info('sending shares beta13 to Server3...')
            s3_address = ('localhost',self.peers['3'])
            socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_obj.connect(s3_address)
            request = "SERVER-1-BETASHARES-"
            socket_obj.send(request.encode())
            for client_id in self.shares_of_betas_for_share_conversion.keys():
                socket_obj.send(client_id.encode())
                for i in range(self.data_dimension):
                    for j in range(self.ring_size):
                        socket_obj.send(self.shares_of_betas_for_share_conversion[client_id][i][j][1].to_bytes(self.num_bytes, sys.byteorder))
    
        self.is_local_computation_of_correlated_tuples_generation_done = True

    def boolean2arithmetic_conversion(self):
        self.is_share_transmission_for_conversion_done = True
   
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

    def compute_l2_norm(self):
        shares_to_send = {}
        for client_id in self.final_converted_arithmetic_shares.keys():
            # generate zero-sharing share
            zero_share = self.zero_sharing()
            y_i = 0
            assert len(self.final_converted_arithmetic_shares[client_id]) == self.data_dimension
            for i in range(self.data_dimension):
                if self.id == 1:
                    y_i = (y_i + self.final_converted_arithmetic_shares[client_id][i][0]* \
                            self.final_converted_arithmetic_shares[client_id][i][0]+ \
                            self.final_converted_arithmetic_shares[client_id][i][0]* \
                            self.final_converted_arithmetic_shares[client_id][i][1]* 2) & self.mask
                else:
                    y_i = (y_i + self.final_converted_arithmetic_shares[client_id][i][1]* \
                            self.final_converted_arithmetic_shares[client_id][i][1]+ \
                            self.final_converted_arithmetic_shares[client_id][i][0]* \
                            self.final_converted_arithmetic_shares[client_id][i][1]* 2) & self.mask
            y_i = (y_i + zero_share) & self.mask 
            shares_to_send[client_id] = y_i 
        if self.id == 1:
            s2_address = ('localhost',self.peers['2'])
            socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_obj.connect(s2_address)
            request = "SERVER-1-NORMCOMPUT-"
            socket_obj.send(request.encode())
            for client_id in shares_to_send.keys():
                self.shares_of_l2_norm[client_id]=[shares_to_send[client_id],0]
                socket_obj.send(client_id.encode())
                socket_obj.send(shares_to_send[client_id].to_bytes(self.num_bytes, sys.byteorder))
        elif self.id == 2:
            s3_address = ('localhost',self.peers['3'])
            socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_obj.connect(s3_address)
            request = "SERVER-2-NORMCOMPUT-"
            socket_obj.send(request.encode())
            for client_id in shares_to_send.keys():
                self.shares_of_l2_norm[client_id]=[0,shares_to_send[client_id]]
                socket_obj.send(client_id.encode())
                socket_obj.send(shares_to_send[client_id].to_bytes(self.num_bytes, sys.byteorder))
        else:
            s1_address = ('localhost',self.peers['1'])
            socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_obj.connect(s1_address)
            request = "SERVER-3-NORMCOMPUT-"
            socket_obj.send(request.encode())
            for client_id in shares_to_send.keys():
                self.shares_of_l2_norm[client_id]=[0,shares_to_send[client_id]]
                socket_obj.send(client_id.encode())
                socket_obj.send(shares_to_send[client_id].to_bytes(self.num_bytes, sys.byteorder))
        self.is_norm_share_computation_done = True
        
    def semihonest_multiplication_batch(self):
        for client_id in self.shares_of_betas_for_share_conversion.keys():
            self.yis_in_multiplication_protocol[client_id] = []
            for i in range(self.data_dimension):
                self.yis_in_multiplication_protocol[client_id].append([])
                for j in range(self.ring_size):
                    zero_share = self.zero_sharing()
                    y_i = 0 
                    y_i += zero_share
                    if self.id == 1:
                        y_i = (y_i + self.shares_of_betas_for_share_conversion[client_id][i][j][0] * \
                               self.shares_of_sigmas_for_share_conversion[client_id][i][j][0] + \
                                self.shares_of_betas_for_share_conversion[client_id][i][j][0] * \
                                self.shares_of_sigmas_for_share_conversion[client_id][i][j][1] + \
                                self.shares_of_betas_for_share_conversion[client_id][i][j][1] * \
                                self.shares_of_sigmas_for_share_conversion[client_id][i][j][0]) & self.mask
                        # self.yis_in_multiplication_protocol[client_id][i].append([y_i, 0])
                        self.yis_in_multiplication_protocol[client_id][i].append(y_i)
                    else:
                        y_i = (y_i + self.shares_of_betas_for_share_conversion[client_id][i][j][1] * \
                               self.shares_of_sigmas_for_share_conversion[client_id][i][j][1] + \
                                self.shares_of_betas_for_share_conversion[client_id][i][j][0] * \
                                self.shares_of_sigmas_for_share_conversion[client_id][i][j][1] + \
                                self.shares_of_betas_for_share_conversion[client_id][i][j][1] * \
                                self.shares_of_sigmas_for_share_conversion[client_id][i][j][0]) & self.mask
                        # self.yis_in_multiplication_protocol[client_id][i].append([0, y_i])
                        self.yis_in_multiplication_protocol[client_id][i].append(y_i)

        self.logger.info('compute 3-out-of-3 additive sharings of epsilons via multiplication protocol done.')
        self.logger.info('sending the 3-out-of-3 additive shares to convert them to replicated sharings...')
        if self.id == 1:
            s2_address = ('localhost',self.peers['2'])
            socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_obj.connect(s2_address)
            request = "SERVER-1-MULTEPSILON"
            socket_obj.send(request.encode())
            for client_id in self.yis_in_multiplication_protocol.keys():
                socket_obj.send(client_id.encode())
                for i in range(self.data_dimension):
                    for j in range(self.ring_size):
                        socket_obj.send(self.yis_in_multiplication_protocol[client_id][i][j][0].to_bytes(self.num_bytes, sys.byteorder))
        elif self.id == 2:
            s3_address = ('localhost',self.peers['3'])
            socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_obj.connect(s3_address)
            request = "SERVER-2-MULTEPSILON"
            socket_obj.send(request.encode())
            for client_id in self.yis_in_multiplication_protocol.keys():
                socket_obj.send(client_id.encode())
                for i in range(self.data_dimension):
                    for j in range(self.ring_size):
                        socket_obj.send(self.yis_in_multiplication_protocol[client_id][i][j][1].to_bytes(self.num_bytes, sys.byteorder))
        else:
            s1_address = ('localhost',self.peers['1'])                    
            socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_obj.connect(s1_address)
            request = "SERVER-3-MULTEPSILON"
            socket_obj.send(request.encode())
            for client_id in self.yis_in_multiplication_protocol.keys():
                socket_obj.send(client_id.encode())
                for i in range(self.data_dimension):
                    for j in range(self.ring_size):
                        socket_obj.send(self.yis_in_multiplication_protocol[client_id][i][j][1].to_bytes(self.num_bytes, sys.byteorder))
        
        self.logger.info('send the 3-out-of-3 additive shares to convert them to replicated sharings done.')
        self.is_multiplication_done = True
    
    # def semihonest_multiplication_batch(self, shares : Dict[str, List[List[List[Union[Tuple[int],List[int]]]]]]):
    #     for client_id in shares.keys():
    #         self.yis_in_multiplication_protocol[client_id] = []
    #         for i in range(self.data_dimension):
    #             self.yis_in_multiplication_protocol[client_id].append([])
    #             assert len(shares[client_id][i]) == 2 and \
    #             len(shares[client_id][i][0]) == self.ring_size and \
    #             len(shares[client_id][i][1]) == self.ring_size
    #             for j in range(self.ring_size):
    #                 zero_share = self.zero_sharing()
    #                 y_i = 0 
    #                 y_i += zero_share
    #                 if self.id == 1:
    #                     y_i = (y_i + shares[client_id][i][0][j][0] * shares[client_id][i][1][j][0] + \
    #                             shares[client_id][i][0][j][0] * shares[client_id][i][1][j][1] + \
    #                             shares[client_id][i][0][j][1] * shares[client_id][i][1][j][0]) & self.mask
    #                     self.yis_in_multiplication_protocol[client_id][i].append([y_i, 0])
    #                 else:
    #                     y_i = (y_i + shares[client_id][i][0][j][1] * shares[client_id][i][1][j][1] + \
    #                             shares[client_id][i][0][j][0] * shares[client_id][i][1][j][1] + \
    #                             shares[client_id][i][0][j][1] * shares[client_id][i][1][j][0]) & self.mask
    #                     self.yis_in_multiplication_protocol[client_id][i].append([0, y_i])

    #     self.logger.info('compute 3-out-of-3 additive sharings of epsilons via multiplication protocol done.')
    #     self.logger.info('sending the 3-out-of-3 additive shares to convert them to replicated sharings...')
    #     if self.id == 1:
    #         s2_address = ('localhost',self.peers['2'])
    #         socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #         socket_obj.connect(s2_address)
    #         request = "SERVER-1-MULTEPSILON"
    #         socket_obj.send(request.encode())
    #         for client_id in self.yis_in_multiplication_protocol.keys():
    #             socket_obj.send(client_id.encode())
    #             for i in range(self.data_dimension):
    #                 for j in range(self.ring_size):
    #                     socket_obj.send(self.yis_in_multiplication_protocol[client_id][i][j][0].to_bytes(self.num_bytes, sys.byteorder))
    #     elif self.id == 2:
    #         s3_address = ('localhost',self.peers['3'])
    #         socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #         socket_obj.connect(s3_address)
    #         request = "SERVER-2-MULTEPSILON"
    #         socket_obj.send(request.encode())
    #         for client_id in self.yis_in_multiplication_protocol.keys():
    #             socket_obj.send(client_id.encode())
    #             for i in range(self.data_dimension):
    #                 for j in range(self.ring_size):
    #                     socket_obj.send(self.yis_in_multiplication_protocol[client_id][i][j][1].to_bytes(self.num_bytes, sys.byteorder))
    #     else:
    #         s1_address = ('localhost',self.peers['1'])                    
    #         socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #         socket_obj.connect(s1_address)
    #         request = "SERVER-3-MULTEPSILON"
    #         socket_obj.send(request.encode())
    #         for client_id in self.yis_in_multiplication_protocol.keys():
    #             socket_obj.send(client_id.encode())
    #             for i in range(self.data_dimension):
    #                 for j in range(self.ring_size):
    #                     socket_obj.send(self.yis_in_multiplication_protocol[client_id][i][j][1].to_bytes(self.num_bytes, sys.byteorder))
        
    #     self.logger.info('send the 3-out-of-3 additive shares to convert them to replicated sharings done.')
    #     self.is_multiplication_done = True

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
        request = self.request.recv(20)

        if request.decode() == REQUESTS[0]: 
            self.logger.info("received request: CLIENT-DATAUPLOADING")
            # receive client id 
            client_id = self.request.recv(4)
            client_id = client_id.decode()
            self.logger.info('received client id: %s',client_id)
            response = 'check'
            self.request.send(response.encode())
            # codes to receive client data
            # receive number of shares
            bytes_num_shares = self.request.recv(3)
            num_shares = int.from_bytes(bytes_num_shares, sys.byteorder)
            self.logger.debug('received number of shares: %s',num_shares)
            self.server.client_data[client_id] = []
            self.server.shares[client_id] = []
            # receive ring size 
            bytes_ring_size = self.request.recv(1)
            self.server.ring_size = int.from_bytes(bytes_ring_size, sys.byteorder)
            # compute the num_bytes 
            self.server.num_bytes = int(self.server.ring_size / 8)
            # compute the mask 
            self.server.mask = pow(2, self.server.ring_size) - 1
            self.logger.debug('received ring size: %s',self.server.ring_size)
            self.logger.debug('number of bytes: %s',self.server.num_bytes)
            if self.server.id == 1:
                # receive data dimension 
                bytes_data_dimension = self.request.recv(3)
                self.server.data_dimension = int.from_bytes(bytes_data_dimension, sys.byteorder)
                self.logger.debug('received data dimension: %s',self.server.data_dimension)
                # receive actual client data 
                for i in range(num_shares):
                    bytes_data_i = self.request.recv(self.server.num_bytes)
                    self.server.client_data[client_id].append(int.from_bytes(bytes_data_i, sys.byteorder))
                    
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

            else:
                self.server.data_dimension = num_shares - 1
                self.logger.debug('received data dimension: %s',self.server.data_dimension)
                # receive the seed
                bytes_seed = self.request.recv(self.server.num_bytes)
                self.server.client_data[client_id].append(int.from_bytes(bytes_seed, sys.byteorder))
                # receive shares 
                seed = int.from_bytes(bytes_seed, sys.byteorder)
                for i in range(self.server.data_dimension):
                    bytes = self.request.recv(self.server.num_bytes)
                    shares_dimension_i = bitarray()
                    # recover bitarray from received bytes
                    shares_dimension_i.frombytes(bytes)
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

            # receive shares of the l2 norm bound 
            if self.server.num_clients_data_received == 0:
                for i in range(2):
                    share = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
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

                self.server.is_uploading_done = True

        # Server 2 requests for shakehanding
        # so this is Server 1, it sends view of inputs to Server 2
        elif request.decode() == REQUESTS[1]: 
            self.logger.info("received request: SERVER-2-SHAKEHAND--")
            response = "check"
            self.request.send(response.encode())
            self.logger.info('shakehand with peer server 2 done.')
            # start to batch-check the inputs 
            request = "SERVER-1-BATCHCHECK-"
            self.request.send(request.encode())
            self.request.send(self.server.views_to_send['inputs'])

        # Server 3 requests for shakehanding
        # so this is Server 1 or Server 2
        elif request.decode() == REQUESTS[2]: 
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
                request = self.request.recv(20)
                assert request.decode() == "SERVER-3-BATCHCHECK-"
                self.server.view_received = self.request.recv(32)

                self.server.is_receive_view_of_inputs_done = True
        
        elif request.decode() == REQUESTS[9]: # Server 1 sends shares of l2 norm 
            self.logger.info('received request: SERVER-1-NORMCOMPUT-')
            for i in range(self.server.num_clients):
                client_id = self.request.recv(4).decode()
                share = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                self.server.received_shares_of_l2_norm[client_id] = share
            self.server.is_receive_l2norm_share_done = True

        elif request.decode() == REQUESTS[10]: # Server 2 sends shares of l2 norm 
            self.logger.info('received request: SERVER-2-NORMCOMPUT-')
            for i in range(self.server.num_clients):
                client_id = self.request.recv(4).decode()
                share = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                self.server.received_shares_of_l2_norm[client_id] = share
            self.server.is_receive_l2norm_share_done = True
            
        elif request.decode() == REQUESTS[11]: # Server 3 sends shares of l2 norm 
            self.logger.info('received request: SERVER-3-NORMCOMPUT-')
            for i in range(self.server.num_clients):
                client_id = self.request.recv(4).decode()
                share = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                self.server.received_shares_of_l2_norm[client_id] = share
            self.server.is_receive_l2norm_share_done = True

        elif request.decode() == REQUESTS[12]: # Server 1 sends 3-out-of-3 additive share to Server 2
            self.logger.info('received request: SERVER-1-MULTEPSILON')
            for i in range(self.server.num_clients):
                client_id = self.request.recv(4).decode()
                self.server.received_yis_in_multiplication_protocol[client_id] = []
                for j in range(self.server.data_dimension):
                    self.server.received_yis_in_multiplication_protocol[client_id].append([])
                    for k in range(self.server.ring_size):
                        share = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                        self.server.received_yis_in_multiplication_protocol[client_id][j].append(share)
            self.server.is_receive_multiplication_share_done = True

        elif request.decode() == REQUESTS[13]: # Server 2 sends 3-out-of-3 additive share to Server 3
            self.logger.info('received request: SERVER-2-MULTEPSILON')
            for i in range(self.server.num_clients):
                client_id = self.request.recv(4).decode()
                self.server.received_yis_in_multiplication_protocol[client_id] = []
                for j in range(self.server.data_dimension):
                    self.server.received_yis_in_multiplication_protocol[client_id].append([])
                    for k in range(self.server.ring_size):
                        share = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                        self.server.received_yis_in_multiplication_protocol[client_id][j].append(share)
            self.server.is_receive_multiplication_share_done = True

        elif request.decode() == REQUESTS[14]: # Server 3 sends 3-out-of-3 additive share to Server 1
            self.logger.info('received request: SERVER-3-MULTEPSILON')
            for i in range(self.server.num_clients):
                client_id = self.request.recv(4).decode()
                self.server.received_yis_in_multiplication_protocol[client_id] = []
                for j in range(self.server.data_dimension):
                    self.server.received_yis_in_multiplication_protocol[client_id].append([])
                    for k in range(self.server.ring_size):
                        share = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                        self.server.received_yis_in_multiplication_protocol[client_id][j].append(share)
            self.server.is_receive_multiplication_share_done = True
              
        # Servers send partial share of differences to open them 
        elif request.decode() == REQUESTS[30] or \
             request.decode() == REQUESTS[31] or \
             request.decode() == REQUESTS[32]:
            if request.decode() == REQUESTS[30]:
                self.logger.info('receive request: SERVER-1-OPENDIFFERE')
            elif request.decode() == REQUESTS[31]:
                self.logger.info('receive request: SERVER-2-OPENDIFFERE')
            else:
                self.logger.info('receive request: SERVER-3-OPENDIFFERE')
            for i in range(self.server.num_clients):
                client_id = self.request.recv(4).decode() 
                share = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                self.server.received_shares_of_differences[client_id] = share
            self.server.is_receive_shares_of_differences_done = True
        
        # Servers send the view of the differences 
        elif request.decode() == REQUESTS[33] or \
             request.decode() == REQUESTS[34] or \
             request.decode() == REQUESTS[35]:
            pass 
                
        # Server 1 sends [\beta]_{13} to Server 3 for share conversion 
        elif request.decode() == REQUESTS[36]:
            self.logger.info('receive request: SERVER-1-BETASHARES-')
            for i in range(self.server.num_clients):
                client_id = self.request.recv(4).decode()
                self.server.received_beta13_for_share_conversion[client_id] = []
                for j in range(self.server.data_dimension):
                    self.server.received_beta13_for_share_conversion[client_id].append([])
                    for k in range(self.server.ring_size):
                        share = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                        self.server.received_beta13_for_share_conversion[client_id][j].append(share)
            self.server.is_receive_share_beta13_done = True
        else:
            self.logger.error("unknown request.")

if __name__ == '__main__':
    import sys 
    import getopt 
    try:
        opts, args = getopt.getopt(sys.argv[1:],"i:p:n:o:",["id=","port=","num_clients=","offline="])
    except getopt.GetoptError as e:
        print(e.msg)
        print(e.opt)
        sys.exit(2)

    id, port, num_clients, offline = 0, 0, 0, 0
    for opt, arg in opts:
        if opt in ("-i","--id"):
            id = int(arg)
        elif opt in ("-p","--port"):
            port = int(arg)
        elif opt in ("-n","--num_clients"):
            num_clients = int(arg)
        elif opt in ("-o","--offline"):
            offline = int(arg)
    
    address_server = ('localhost', port) 
    server = ThreadedServer(id=id, num_clients=num_clients,offline=offline, 
                            address=address_server, handler_class=ThreadedRequestHandler)
    server.serve_forever()



