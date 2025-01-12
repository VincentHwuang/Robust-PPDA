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
from typing import Tuple, List, Dict
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
            "SERVER-1-MULTIBATCH1","SERVER-2-MULTIBATCH1","SERVER-3-MULTIBATCH1",
            "SERVER-1-MULTIBATCH2","SERVER-2-MULTIBATCH2","SERVER-3-MULTIBATCH2",
            "SERVER-1-OPENSHARES-","SERVER-2-OPENSHARES-","SERVER-3-OPENSHARES-",
            "SERVER-1-CHECKVIEWS-","SERVER-2-CHECKVIEWS-","SERVER-3-CHECKVIEWS-",
            "SERVER-1-OPENV------","SERVER-2-OPENV------","SERVER-3-OPENV------",
            "SERVER-1-CHECKVIEWV-","SERVER-2-CHECKVIEWV-","SERVER-3-CHECKVIEWV-",
            # "SERVER-1-BOOLEANSHAR","SERVER-2-BOOLEANSHAR","SERVER-3-BOOLEANSHAR",
            # "SERVER-1-HASHBOOLEAN","SERVER-2-HASHBOOLEAN","SERVER-3-HASHBOOLEAN",
            # "SERVER-1-INTERMEDIAT","SERVER-2-INTERMEDIAT","SERVER-3-INTERMEDIAT",
            "SERVER-1-OPENDIFFERE","SERVER-2-OPENDIFFERE","SERVER-3-OPENDIFFERE",
            "SERVER-1-VIEWDIFFERE","SERVER-2-VIEWDIFFERE","SERVER-3-VIEWDIFFERE")

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
    def __init__(self, id, num_clients, address, handler_class):
        self.id = id
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
        self.shares_of_beaver_triples_ais = {}
        self.shares_of_beaver_triples_cis = {}
        self.views_to_send = {}
        self.views_to_comp = {}
        self.shares_received_for_conversion = {}
        self.arithmetic_shares_for_conversion = {}
        self.data_dimension = 0
        self.num_clients_data_received = 0
        self.num_shares_for_conversion_received = 0
        self.shares_of_l2_norm = {}
        self.received_shares_of_l2_norm = {}
        self.yis_in_multiplication_protocol_layer1 = {}
        self.yis_in_multiplication_protocol_layer2 = {}
        self.received_yis_in_multiplication_protocol_layer1 = {}
        self.received_yis_in_multiplication_protocol_layer2 = {}
        self.is_uploading_done = False
        self.is_input_batchcheck_done = False
        self.is_handshaking_in_progress = False
        self.is_component_wise_bounding_in_progress = False
        self.is_component_wise_bounding_done = False
        self.is_share_conversion_in_progress = False
        self.is_share_transmission_for_conversion_done = False
        self.is_multiplication_in_progress = False
        self.is_norm_share_computation_done = False
        self.is_layer1_multiplication_done = False
        self.is_layer2_multiplication_done = False
        self.is_receive_multiplication_share_done = False
        self.is_receive_layer1_multiplication_share_done = False
        self.is_receive_layer2_multiplication_share_done = False
        self.is_receive_l2norm_share_done = False
        self.is_sigma_computation_in_progress = False
        self.is_x_computation_in_progress = False
        self.is_norm_computation_correctness_check_in_progress = False
        self.shares_of_sigmas = {}
        self.shares_of_xs = {}
        self.shares_of_rhois = {}
        self.shares_of_sigmais = {}
        self.rhois = {}
        self.sigmais = {}
        self.received_shares_rhois = {}
        self.received_shares_sigmais = {}
        self.is_receive_shares_rhois_sigmais_done = False
        self.is_receive_views_of_opened_rhois_sigmais_done = False
        self.views_of_opened_rhois_sigmais = {}
        self.received_views_of_opened_rhois_sigmais = {}
        self.final_converted_arithmetic_shares = {}
        self.alpha = 0
        self.shares_of_v = {}
        self.received_share_v = {}
        self.is_receive_share_v_done = False
        self.is_receive_view_of_vs_done = False
        self.vs = {}
        self.view_of_vs = b''
        self.received_view_of_vs = b''
        self.client_id_chosen = ''
        self.share_mu2 = [0,0]
        self.zs = {}
        self.shares_of_arithmetic_z_shares = {}
        self.is_receive_boolean_share_done = False
        self.is_receive_boolean_share_hash_done = False
        self.received_hash_of_z_shares = b''
        # variables for Boolean addition 
        # self.carry_bits_1 = {}
        # self.carry_bits_2 = {}
        # self.two_server_shares_1 = {}
        # self.one_server_shares_1 = {}
        # self.received_one_server_shares_1 = {}
        # self.two_server_shares_2 = {}
        # self.one_server_shares_2 = {}
        # self.is_receive_one_server_shares_1_done = False
        self.received_shares_of_differences = {}
        self.is_receive_shares_of_differences_done = False
        self.is_receive_view_of_differences_done = False
        self.differences = {}
        self.view_of_differences = b''
        self.received_view_of_differences = b''
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

            if self.is_input_batchcheck_done == True and self.is_component_wise_bounding_in_progress == False:
                self.is_component_wise_bounding_in_progress = True
                self.logger.info('enter the second phase: norm-bounding based selection...')
                self.logger.info('start to enforce component wise bounding...')
                thread = threading.Thread(target=self.component_wise_bounding, args=())
                thread.start()

            if self.is_component_wise_bounding_done == True and self.is_share_conversion_in_progress == False:
                self.is_share_conversion_in_progress = True
                self.logger.info('start to convert shares...')
                thread = threading.Thread(target=self.boolean2arithmetic_conversion, args=())
                thread.start()

            if self.is_share_transmission_for_conversion_done == True and self.is_multiplication_in_progress == False:
                self.is_multiplication_in_progress = True
                self.logger.info('start to compute layer1 intermediate product in a batch manner...')
                shares = self.arithmetic_shares_for_conversion
                thread = threading.Thread(target=self.semihonest_multiplication_batch, args=(shares, 'layer1'))
                thread.start()

            if self.is_layer1_multiplication_done == True and self.is_receive_layer1_multiplication_share_done == True and self.is_sigma_computation_in_progress == False:
                self.is_sigma_computation_in_progress = True
                self.logger.info('recombine the shares of layer1 intermediate products...')
                for client_id in self.yis_in_multiplication_protocol_layer1.keys():
                    assert len(self.yis_in_multiplication_protocol_layer1[client_id]) == len(self.received_yis_in_multiplication_protocol_layer1[client_id])
                    for j in range(len(self.yis_in_multiplication_protocol_layer1[client_id])):
                        if self.id == 1:
                            self.yis_in_multiplication_protocol_layer1[client_id][j][1] = self.received_yis_in_multiplication_protocol_layer1[client_id][j]
                        else:
                            self.yis_in_multiplication_protocol_layer1[client_id][j][0] = self.received_yis_in_multiplication_protocol_layer1[client_id][j]
                
                # compute sharing of sigmas
                self.compute_sharings_of_sigmas()

                # compute product of sigmas and xi23
                shares = {}
                assert self.arithmetic_shares_for_conversion.keys() == self.shares_of_sigmas.keys()
                for client_id in self.arithmetic_shares_for_conversion.keys():
                    shares[client_id] = []
                    assert len(self.arithmetic_shares_for_conversion[client_id]) == len(self.shares_of_sigmas[client_id])
                    for i in range(len(self.shares_of_sigmas[client_id])):
                        shares[client_id].append([])
                        shares[client_id][i].append(self.shares_of_sigmas[client_id][i])
                        shares[client_id][i].append(self.arithmetic_shares_for_conversion[client_id][i][2])
                    
                self.logger.info('start to compute layer2 intermediate product in a batch manner...')
                thread = threading.Thread(target=self.semihonest_multiplication_batch,args=(shares,'layer2'))
                thread.start()

            if self.is_layer2_multiplication_done == True and self.is_receive_layer2_multiplication_share_done == True and self.is_x_computation_in_progress == False:
                self.is_x_computation_in_progress = True
                self.logger.info('recombine the shares of layer2 intermediate products...')
                for client_id in self.yis_in_multiplication_protocol_layer2.keys():
                    for j in range(len(self.yis_in_multiplication_protocol_layer2[client_id])):
                        if self.id == 1:
                            self.yis_in_multiplication_protocol_layer2[client_id][j][1] = self.received_yis_in_multiplication_protocol_layer2[client_id][j]
                        else:
                            self.yis_in_multiplication_protocol_layer2[client_id][j][0] = self.received_yis_in_multiplication_protocol_layer2[client_id][j]

                # compute sharings of xs
                self.compute_sharings_of_xs()

                # compute the final arithmetic shares 
                self.compute_final_converted_arithmetic_shares()

                # compute l2 norm and send corresponding shares
                self.compute_l2_norm()

            if self.is_norm_share_computation_done == True and self.is_receive_l2norm_share_done == True and self.is_norm_computation_correctness_check_in_progress == False:
                self.is_norm_computation_correctness_check_in_progress = True 
                self.logger.info('recombining the shares of l2 norm...')
                for client_id in self.shares_of_l2_norm.keys():
                    if self.id == 1:
                        self.shares_of_l2_norm[client_id][1] = self.received_shares_of_l2_norm[client_id]
                    else:
                        self.shares_of_l2_norm[client_id][0] = self.received_shares_of_l2_norm[client_id]
                    
                # generate alpha 
                self.logger.info('generating common non-zero element alpha...')
                while self.alpha == 0:
                    ctrS_bytes = self.PRF_counters[2].to_bytes(8, sys.byteorder)
                    hmac_obj = hmac.HMAC(self.keys[2], hashes.SHA256())
                    hmac_obj.update(ctrS_bytes)
                    self.alpha = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                    self.PRF_counters[2] += 1
                
                # compute shares of rhois and sigmais for norm check 
                self.logger.info('computing shares of rhois and sigmais for norm check...')
                for client_id in self.shares_of_beaver_triples_ais.keys():
                    self.client_id_chosen = client_id
                    break
                assert len(self.shares_of_beaver_triples_ais[self.client_id_chosen]) == self.data_dimension and \
                    len(self.shares_of_beaver_triples_cis[self.client_id_chosen]) == self.data_dimension
                for client_id in self.final_converted_arithmetic_shares.keys():
                    self.shares_of_rhois[client_id] = []
                    self.shares_of_sigmais[client_id] = []
                    assert len(self.final_converted_arithmetic_shares[client_id]) == self.data_dimension
                    for i in range(self.data_dimension):
                        rhoi_1 = (self.alpha * self.final_converted_arithmetic_shares[client_id][i][0] + \
                                  self.shares_of_beaver_triples_ais[self.client_id_chosen][i][0]) & self.mask
                        rhoi_2 = (self.alpha * self.final_converted_arithmetic_shares[client_id][i][1] + \
                                  self.shares_of_beaver_triples_ais[self.client_id_chosen][i][1]) & self.mask
                        sigmai_1 = (self.final_converted_arithmetic_shares[client_id][i][0] + \
                                    self.shares_of_beaver_triples_ais[self.client_id_chosen][i][0]) & self.mask
                        sigmai_2 = (self.final_converted_arithmetic_shares[client_id][i][1] + \
                                    self.shares_of_beaver_triples_ais[self.client_id_chosen][i][1]) & self.mask
                        self.shares_of_rhois[client_id].append((rhoi_1,rhoi_2))
                        self.shares_of_sigmais[client_id].append((sigmai_1,sigmai_2)) 

                # open rhois and sigmais 
                self.logger.info('opening rhois and sigmais...')                       
                if self.id == 1:
                    s2_address = ('localhost',self.peers['2'])
                    socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_obj.connect(s2_address)
                    request = "SERVER-1-OPENSHARES-"
                    socket_obj.send(request.encode())
                    for client_id in self.shares_of_rhois.keys():
                        socket_obj.send(client_id.encode())
                        for i in range(self.data_dimension):
                            socket_obj.send(self.shares_of_rhois[client_id][i][1].to_bytes(self.num_bytes, sys.byteorder))
                            socket_obj.send(self.shares_of_sigmais[client_id][i][1].to_bytes(self.num_bytes, sys.byteorder))
                elif self.id == 2:
                    s3_address = ('localhost',self.peers['3'])
                    socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_obj.connect(s3_address)
                    request = "SERVER-2-OPENSHARES-"
                    socket_obj.send(request.encode())
                    for client_id in self.shares_of_rhois.keys():
                        socket_obj.send(client_id.encode())
                        for i in range(self.data_dimension):
                            socket_obj.send(self.shares_of_rhois[client_id][i][0].to_bytes(self.num_bytes, sys.byteorder))
                            socket_obj.send(self.shares_of_sigmais[client_id][i][0].to_bytes(self.num_bytes, sys.byteorder))
                else:
                    s1_address = ('localhost',self.peers['1'])
                    socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_obj.connect(s1_address)
                    request = "SERVER-3-OPENSHARES-"
                    socket_obj.send(request.encode())
                    for client_id in self.shares_of_rhois.keys():
                        socket_obj.send(client_id.encode())
                        for i in range(self.data_dimension):
                            socket_obj.send(self.shares_of_rhois[client_id][i][0].to_bytes(self.num_bytes, sys.byteorder))
                            socket_obj.send(self.shares_of_sigmais[client_id][i][0].to_bytes(self.num_bytes, sys.byteorder))

            if self.is_receive_shares_rhois_sigmais_done == True:
                self.is_receive_shares_rhois_sigmais_done = False
                self.logger.info('recovering rhois and sigmais...')
                for client_id in self.shares_of_rhois.keys():
                    self.rhois[client_id] = []
                    self.sigmais[client_id] = []
                    for i in range(self.data_dimension):
                        rho_i = (self.shares_of_rhois[client_id][i][0] + \
                                 self.shares_of_rhois[client_id][i][1] + \
                                 self.received_shares_rhois[client_id][i]) & self.mask
                        sigma_i = (self.shares_of_sigmais[client_id][i][0] + \
                                   self.shares_of_sigmais[client_id][i][1] + \
                                   self.received_shares_sigmais[client_id][i]) & self.mask
                        self.rhois[client_id].append(rho_i)
                        self.sigmais[client_id].append(sigma_i)

                self.logger.info('exchanging the views of opened rhois and sigmais...')
                # compute the view
                for client_id in self.rhois.keys():
                    bytes = b''
                    for i in range(self.data_dimension):
                        bytes += self.rhois[client_id][i].to_bytes(self.num_bytes, sys.byteorder)
                        bytes += self.sigmais[client_id][i].to_bytes(self.num_bytes, sys.byteorder)
                    hash_obj = hashes.Hash(hashes.SHA256())
                    hash_obj.update(bytes)
                    self.views_of_opened_rhois_sigmais[client_id] = hash_obj.finalize()
                # send the views 
                if self.id == 1:
                    s2_address = ('localhost',self.peers['2'])
                    socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_obj.connect(s2_address)
                    request = "SERVER-1-CHECKVIEWS-"
                    socket_obj.send(request.encode())
                    for client_id in self.views_of_opened_rhois_sigmais.keys():
                        socket_obj.send(client_id.encode())
                        socket_obj.send(self.views_of_opened_rhois_sigmais[client_id])
                elif self.id == 2:
                    s3_address = ('localhost',self.peers['3'])
                    socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_obj.connect(s3_address)
                    request = "SERVER-2-CHECKVIEWS-"
                    socket_obj.send(request.encode())
                    for client_id in self.views_of_opened_rhois_sigmais.keys():
                        socket_obj.send(client_id.encode())
                        socket_obj.send(self.views_of_opened_rhois_sigmais[client_id])
                else:
                    s1_address = ('localhost',self.peers['1'])
                    socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_obj.connect(s1_address)
                    request = "SERVER-3-CHECKVIEWS-"
                    socket_obj.send(request.encode())
                    for client_id in self.views_of_opened_rhois_sigmais.keys():
                        socket_obj.send(client_id.encode())
                        socket_obj.send(self.views_of_opened_rhois_sigmais[client_id])

            if self.is_receive_views_of_opened_rhois_sigmais_done == True:
                self.is_receive_views_of_opened_rhois_sigmais_done = False 
                consistency_flag = True
                for client_id in self.views_of_opened_rhois_sigmais.keys():
                    if self.views_of_opened_rhois_sigmais[client_id] == self.received_views_of_opened_rhois_sigmais[client_id]:
                        self.logger.info("view of opened rhois and sigmais of client %s is consistent.",client_id)
                    else:
                        consistency_flag = False
                        self.logger.error("view of opened rhois and sigmais of client %s is inconsistent!",client_id)

                if consistency_flag == True:
                    # compute share of v
                    self.logger.info('computing v...')
                    # self.logger.debug('shares of ais of client %s:\n%s',self.client_id_chosen,self.shares_of_beaver_triples_ais[self.client_id_chosen])
                    # self.logger.debug('shares of cis of client %s:\n%s',self.client_id_chosen,self.shares_of_beaver_triples_cis[self.client_id_chosen])
                    for client_id in self.shares_of_l2_norm.keys():
                        alpha_y_share_1 = self.alpha * self.shares_of_l2_norm[client_id][0]
                        alpha_y_share_2 = self.alpha * self.shares_of_l2_norm[client_id][1]
                        ci_share_1 = 0
                        ci_share_2 = 0
                        part3_share_1 = 0
                        part3_share_2 = 0
                        for i in range(self.data_dimension):
                            ci_share_1 = (ci_share_1 + self.shares_of_beaver_triples_cis[self.client_id_chosen][i][0]) & self.mask
                            ci_share_2 = (ci_share_2 + self.shares_of_beaver_triples_cis[self.client_id_chosen][i][1]) & self.mask
                            if self.id == 1 or self.id == 2:
                                part3_share_1 = (part3_share_1 + \
                                             self.sigmais[client_id][i] * self.shares_of_beaver_triples_ais[self.client_id_chosen][i][0] + \
                                             self.rhois[client_id][i] * self.shares_of_beaver_triples_ais[self.client_id_chosen][i][0] - \
                                             self.rhois[client_id][i] * self.sigmais[client_id][i]) & self.mask
                            else:
                                part3_share_1 = (part3_share_1 + \
                                             self.sigmais[client_id][i] * self.shares_of_beaver_triples_ais[self.client_id_chosen][i][0] + \
                                             self.rhois[client_id][i] * self.shares_of_beaver_triples_ais[self.client_id_chosen][i][0]) & self.mask
                            part3_share_2 = (part3_share_2 + \
                                             self.sigmais[client_id][i] * self.shares_of_beaver_triples_ais[self.client_id_chosen][i][1] + \
                                             self.rhois[client_id][i] * self.shares_of_beaver_triples_ais[self.client_id_chosen][i][1]) & self.mask
                        v_share_1 = (alpha_y_share_1 - ci_share_1 + part3_share_1) & self.mask
                        v_share_2 = (alpha_y_share_2 - ci_share_2 + part3_share_2) & self.mask 
                        self.shares_of_v[client_id] = (v_share_1,v_share_2)

                        # self.logger.debug('shares of v of client %s: %s',client_id,self.shares_of_v[client_id])

                    # open v
                    self.logger.info('opening v...')
                    if self.id == 1:
                        s2_address = ('localhost',self.peers['2'])
                        socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                        socket_obj.connect(s2_address)
                        request = "SERVER-1-OPENV------"
                        socket_obj.send(request.encode())
                        for client_id in self.shares_of_v.keys():
                            socket_obj.send(client_id.encode())
                            socket_obj.send(self.shares_of_v[client_id][1].to_bytes(self.num_bytes, sys.byteorder))
                    elif self.id == 2:
                        s3_address = ('localhost',self.peers['3'])
                        socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                        socket_obj.connect(s3_address)
                        request = "SERVER-2-OPENV------"
                        socket_obj.send(request.encode())
                        for client_id in self.shares_of_v.keys():
                            socket_obj.send(client_id.encode())
                            socket_obj.send(self.shares_of_v[client_id][0].to_bytes(self.num_bytes, sys.byteorder))
                    else:
                        s1_address = ('localhost',self.peers['1'])
                        socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                        socket_obj.connect(s1_address)
                        request = "SERVER-3-OPENV------"
                        socket_obj.send(request.encode())
                        for client_id in self.shares_of_v.keys():
                            socket_obj.send(client_id.encode())
                            socket_obj.send(self.shares_of_v[client_id][0].to_bytes(self.num_bytes, sys.byteorder))

            if self.is_receive_share_v_done == True:
                self.is_receive_share_v_done = False
                for client_id in self.shares_of_v.keys():
                    self.vs[client_id] = (self.shares_of_v[client_id][0] + \
                                          self.shares_of_v[client_id][1] + \
                                            self.received_share_v[client_id]) & self.mask
                # compute the view of vs
                bytes = b''
                for client_id in self.vs.keys():
                    bytes += self.vs[client_id].to_bytes(self.num_bytes, sys.byteorder)
                hash_obj = hashes.Hash(hashes.SHA256())
                hash_obj.update(bytes)
                self.view_of_vs = hash_obj.finalize()
                # send the view 
                if self.id == 1: 
                    address = ('localhost',self.peers['2'])
                    request = "SERVER-1-CHECKVIEWV-"
                elif self.id == 2: 
                    address = ('localhost',self.peers['3'])
                    request = "SERVER-2-CHECKVIEWV-"
                else: 
                    address = ('localhost',self.peers['1'])
                    request = "SERVER-3-CHECKVIEWV-"
                socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                socket_obj.connect(address)
                socket_obj.send(request.encode())
                socket_obj.send(self.view_of_vs)

            if self.is_receive_view_of_vs_done == True:
                self.is_receive_view_of_vs_done = False 
                if self.view_of_vs == self.received_view_of_vs:
                    self.logger.info('view of vs is consistent.')
                else:
                    self.logger.error('view of vs is inconsistent!')
                correctness_flag = True 
                for client_id in self.vs.keys():
                    if self.vs[client_id] != 0:
                        correctness_flag = False
                if correctness_flag == True:
                    self.logger.info('all computations of l2 norm are correct.')
                else:
                    self.logger.error('At least one of the computations of l2 norm is incorrect!')

                # enforce l2 norm bounding 
                # compute the sharing of difference between the norm and the bound 
                self.logger.info('computing shares of difference between the l2 norm and specified bound...')
                # self.logger.debug('shares of mu2: %s',self.share_mu2)
                for client_id in self.shares_of_l2_norm.keys():
                    self.zs[client_id] = ((self.shares_of_l2_norm[client_id][0] - self.share_mu2[0]) & self.mask,\
                                          (self.shares_of_l2_norm[client_id][1] - self.share_mu2[1]) & self.mask) 
                    # self.logger.debug('shares of l2 norm of client %s: %s',client_id,self.shares_of_l2_norm[client_id])
                    # self.logger.debug('share of l2 norm of client %s: %s',client_id,self.shares_of_l2_norm[client_id])
                    # self.logger.debug('share of difference of client %s: %s',client_id,self.zs[client_id])
                    
                    """
                    # generate boolean shares of each arithmetic share   
                    self.shares_of_arithmetic_z_shares[client_id] = [None,None,None]
                    if self.id == 1 or self.id == 2:
                        # generate shares of z12
                        ctr12_bytes = self.PRF_counters[0].to_bytes(8, sys.byteorder)
                        hmac_obj = hmac.HMAC(self.keys[0], hashes.SHA256())
                        hmac_obj.update(ctr12_bytes)
                        z12_12 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        self.PRF_counters[0] += 1

                        ctr12_bytes = self.PRF_counters[0].to_bytes(8, sys.byteorder)
                        hmac_obj = hmac.HMAC(self.keys[0], hashes.SHA256())
                        hmac_obj.update(ctr12_bytes)
                        z12_13 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        self.PRF_counters[0] += 1

                        z12_23 = self.zs[client_id][0] ^ z12_12 ^ z12_13
                        self.shares_of_arithmetic_z_shares[client_id][0] = (z12_12,z12_13,z12_23)

                    if self.id == 1 or self.id == 3:
                        # generate shares of z13 
                        ctr13_bytes = self.PRF_counters[1].to_bytes(8, sys.byteorder)
                        hmac_obj = hmac.HMAC(self.keys[1], hashes.SHA256())
                        hmac_obj.update(ctr13_bytes)
                        z13_12 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        self.PRF_counters[1] += 1

                        ctr13_bytes = self.PRF_counters[1].to_bytes(8, sys.byteorder)
                        hmac_obj = hmac.HMAC(self.keys[1], hashes.SHA256())
                        hmac_obj.update(ctr13_bytes)
                        z13_13 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        self.PRF_counters[1] += 1

                        z13_23 = self.zs[client_id][1] ^ z13_12 ^ z13_13
                        self.shares_of_arithmetic_z_shares[client_id][1] = (z13_12,z13_13,z13_23)

                    if self.id == 2 or self.id == 3:
                        # generate shares of z23 
                        if self.id == 2:
                            ctr23_bytes = self.PRF_counters[1].to_bytes(8, sys.byteorder)
                            hmac_obj = hmac.HMAC(self.keys[1], hashes.SHA256())
                        else:
                            ctr23_bytes = self.PRF_counters[0].to_bytes(8, sys.byteorder)
                            hmac_obj = hmac.HMAC(self.keys[0], hashes.SHA256())
                        hmac_obj.update(ctr23_bytes)
                        z23_12 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        if self.id == 2: self.PRF_counters[1] += 1
                        else: self.PRF_counters[0] += 1

                        if self.id == 2:
                            ctr23_bytes = self.PRF_counters[1].to_bytes(8, sys.byteorder)
                            hmac_obj = hmac.HMAC(self.keys[1], hashes.SHA256())
                        else:
                            ctr23_bytes = self.PRF_counters[0].to_bytes(8, sys.byteorder)
                            hmac_obj = hmac.HMAC(self.keys[0], hashes.SHA256())
                        hmac_obj.update(ctr23_bytes)
                        z23_13 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        if self.id == 2: self.PRF_counters[1] += 1
                        else: self.PRF_counters[0] += 1
 
                        if self.id == 2: z23_23 = self.zs[client_id][1] ^ z23_12 ^ z23_13
                        else: z23_23 = self.zs[client_id][0] ^ z23_12 ^ z23_13

                        self.shares_of_arithmetic_z_shares[client_id][2] = (z23_12,z23_13,z23_23)

                self.logger.info('exchanging boolean shares of z shares...')
                # send shares to corresponding servers 
                # Server 1 sends (z12_23,z12_13) to Server 3
                # sends h(z13_12||z13_23) to Server 2 
                if self.id == 1: 
                    s3_address = ('localhost',self.peers['3'])
                    s2_address = ('localhost',self.peers['2'])

                    socket_obj1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_obj1.connect(s3_address)
                    request1 = "SERVER-1-BOOLEANSHAR"
                    socket_obj1.send(request1.encode())

                    socket_obj2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_obj2.connect(s2_address)
                    request2 = "SERVER-1-HASHBOOLEAN"
                    socket_obj2.send(request2.encode())
                    bytes = b''
                    for client_id in self.shares_of_arithmetic_z_shares.keys():
                        socket_obj1.send(client_id.encode())
                        socket_obj1.send(self.shares_of_arithmetic_z_shares[client_id][0][2].to_bytes(self.num_bytes, sys.byteorder))
                        socket_obj1.send(self.shares_of_arithmetic_z_shares[client_id][0][1].to_bytes(self.num_bytes, sys.byteorder))
                        bytes += self.shares_of_arithmetic_z_shares[client_id][1][0].to_bytes(self.num_bytes, sys.byteorder)
                        bytes += self.shares_of_arithmetic_z_shares[client_id][1][2].to_bytes(self.num_bytes, sys.byteorder)
                    hash_obj = hashes.Hash(hashes.SHA256())                                        
                    hash_obj.update(bytes)
                    socket_obj2.send(hash_obj.finalize())

                # Server 2 sends h(z12_23||z12_13) to Server 3
                # Server 2 sends (z23_12,z23_13) to Server 1
                elif self.id == 2: 
                    s3_address = ('localhost',self.peers['3'])
                    s1_address = ('localhost',self.peers['1'])

                    socket_obj1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_obj1.connect(s3_address)
                    request1 = "SERVER-2-HASHBOOLEAN"
                    socket_obj1.send(request1.encode())

                    socket_obj2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_obj2.connect(s1_address)
                    request2 = "SERVER-2-BOOLEANSHAR"
                    socket_obj2.send(request2.encode())
                    bytes = b''
                    for client_id in self.shares_of_arithmetic_z_shares.keys():
                        socket_obj2.send(client_id.encode())
                        bytes += self.shares_of_arithmetic_z_shares[client_id][0][2].to_bytes(self.num_bytes, sys.byteorder)
                        bytes += self.shares_of_arithmetic_z_shares[client_id][0][1].to_bytes(self.num_bytes, sys.byteorder)
                        socket_obj2.send(self.shares_of_arithmetic_z_shares[client_id][2][0].to_bytes(self.num_bytes, sys.byteorder))
                        socket_obj2.send(self.shares_of_arithmetic_z_shares[client_id][2][1].to_bytes(self.num_bytes, sys.byteorder))
                    hash_obj = hashes.Hash(hashes.SHA256())
                    hash_obj.update(bytes)
                    socket_obj1.send(hash_obj.finalize())
                # Server 3 sends (z13_12,z13_23) to Server 2 
                # sends h(z23_12||z23_13) to Server 1
                else:
                    s2_address = ('localhost',self.peers['2'])
                    s1_address = ('localhost',self.peers['1'])

                    socket_obj1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_obj1.connect(s2_address)
                    request1 = "SERVER-3-BOOLEANSHAR"
                    socket_obj1.send(request1.encode())

                    socket_obj2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_obj2.connect(s1_address)
                    request2 = "SERVER-3-HASHBOOLEAN"
                    socket_obj2.send(request2.encode())
                    bytes = b''
                    for client_id in self.shares_of_arithmetic_z_shares.keys():
                        socket_obj1.send(client_id.encode())
                        socket_obj1.send(self.shares_of_arithmetic_z_shares[client_id][1][0].to_bytes(self.num_bytes, sys.byteorder))
                        socket_obj1.send(self.shares_of_arithmetic_z_shares[client_id][1][2].to_bytes(self.num_bytes, sys.byteorder))
                        bytes += self.shares_of_arithmetic_z_shares[client_id][2][0].to_bytes(self.num_bytes, sys.byteorder)
                        bytes += self.shares_of_arithmetic_z_shares[client_id][2][1].to_bytes(self.num_bytes, sys.byteorder)
                    hash_obj = hashes.Hash(hashes.SHA256())                                        
                    hash_obj.update(bytes)
                    socket_obj2.send(hash_obj.finalize())
                    """

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

            if self.is_receive_shares_of_differences_done == True:
                self.is_receive_shares_of_differences_done = False 
                self.logger.info('checking the view of differences...')
                bytes = b''
                for client_id in self.zs.keys():
                    self.differences[client_id] = (self.zs[client_id][0] + self.zs[client_id][1] + self.received_shares_of_differences[client_id]) & self.mask
                    bytes += self.differences[client_id].to_bytes(self.num_bytes, sys.byteorder)
                hash_obj = hashes.Hash(hashes.SHA256())
                hash_obj.update(bytes)
                self.view_of_differences = hash_obj.finalize()
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
                socket_obj.send(self.view_of_differences)
            
            if self.is_receive_view_of_differences_done == True:
                self.is_receive_view_of_differences_done = False 
                if self.view_of_differences == self.received_view_of_differences:
                    self.logger.info('the view of differences is consistent.')
                    self.logger.info('aggregating data of valid clients...')
                    aggregation = [[0,0] for i in range(self.data_dimension)]
                    num_clients_involved = 0
                    for client_id in self.differences.keys():
                        # self.logger.debug('arithmetic shares of data of client %s:\n%s',client_id,self.final_converted_arithmetic_shares[client_id])
                        difference = int_from_twos_complement(int_to_twos_complement(self.differences[client_id], self.ring_size), self.ring_size)
                        self.logger.debug('difference of client %s: %s', client_id,difference)
                        if difference <= 0:
                            for i in range(self.data_dimension):
                                aggregation[i][0] = (aggregation[i][0] + self.final_converted_arithmetic_shares[client_id][i][0]) & self.mask
                                aggregation[i][1] = (aggregation[i][1] + self.final_converted_arithmetic_shares[client_id][i][1]) & self.mask
                            num_clients_involved += 1
                    # division 
                    # aggregation_array = np.array(aggregation, dtype=object)
                    # aggregation = aggregation_array // num_clients_involved

                    self.logger.debug('aggregation: %s',aggregation)

                    # reset all variables
                    self.ring_size = 0
                    self.num_bytes = 0
                    self.mask = 0
                    self.client_data = {}
                    self.shares = {}
                    self.shares_of_beaver_triples_ais = {}
                    self.shares_of_beaver_triples_cis = {}
                    self.views_to_send = {}
                    self.views_to_comp = {}
                    self.shares_received_for_conversion = {}
                    self.arithmetic_shares_for_conversion = {}
                    self.data_dimension = 0
                    self.num_clients_data_received = 0
                    self.num_shares_for_conversion_received = 0
                    self.shares_of_l2_norm = {}
                    self.received_shares_of_l2_norm = {}
                    self.yis_in_multiplication_protocol_layer1 = {}
                    self.yis_in_multiplication_protocol_layer2 = {}
                    self.received_yis_in_multiplication_protocol_layer1 = {}
                    self.received_yis_in_multiplication_protocol_layer2 = {}
                    self.is_uploading_done = False
                    self.is_input_batchcheck_done = False
                    self.is_handshaking_in_progress = False
                    self.is_component_wise_bounding_in_progress = False
                    self.is_component_wise_bounding_done = False
                    self.is_share_conversion_in_progress = False
                    self.is_share_transmission_for_conversion_done = False
                    self.is_multiplication_in_progress = False
                    self.is_norm_share_computation_done = False
                    self.is_layer1_multiplication_done = False
                    self.is_layer2_multiplication_done = False
                    self.is_receive_multiplication_share_done = False
                    self.is_receive_layer1_multiplication_share_done = False
                    self.is_receive_layer2_multiplication_share_done = False
                    self.is_receive_l2norm_share_done = False
                    self.is_sigma_computation_in_progress = False
                    self.is_x_computation_in_progress = False
                    self.is_norm_computation_correctness_check_in_progress = False
                    self.shares_of_sigmas = {}
                    self.shares_of_xs = {}
                    self.shares_of_rhois = {}
                    self.shares_of_sigmais = {}
                    self.rhois = {}
                    self.sigmais = {}
                    self.received_shares_rhois = {}
                    self.received_shares_sigmais = {}
                    self.is_receive_shares_rhois_sigmais_done = False
                    self.is_receive_views_of_opened_rhois_sigmais_done = False
                    self.views_of_opened_rhois_sigmais = {}
                    self.received_views_of_opened_rhois_sigmais = {}
                    self.final_converted_arithmetic_shares = {}
                    self.alpha = 0
                    self.shares_of_v = {}
                    self.received_share_v = {}
                    self.is_receive_share_v_done = False
                    self.is_receive_view_of_vs_done = False
                    self.vs = {}
                    self.view_of_vs = b''
                    self.received_view_of_vs = b''
                    self.client_id_chosen = ''
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
                    self.view_of_differences = b''
                    self.received_view_of_differences = b''
                else:
                    self.logger.error('the view of differences is inconsistent!')
            """
            if self.is_receive_boolean_share_done == True and self.is_receive_boolean_share_hash_done == True:
                self.is_receive_boolean_share_done = False
                self.is_receive_boolean_share_hash_done = False 
                # check the consistency of shares          
                bytes = b''         
                for client_id in self.shares_of_arithmetic_z_shares.keys():
                    if self.id == 1:
                        bytes += self.shares_of_arithmetic_z_shares[client_id][2][0].to_bytes(self.num_bytes, sys.byteorder)
                        bytes += self.shares_of_arithmetic_z_shares[client_id][2][1].to_bytes(self.num_bytes, sys.byteorder)
                        self.shares_of_arithmetic_z_shares[client_id][0] = (self.shares_of_arithmetic_z_shares[client_id][0][0],self.shares_of_arithmetic_z_shares[client_id][0][1])
                        self.shares_of_arithmetic_z_shares[client_id][1] = (self.shares_of_arithmetic_z_shares[client_id][1][0],self.shares_of_arithmetic_z_shares[client_id][1][1])
                    elif self.id == 2:
                        bytes += self.shares_of_arithmetic_z_shares[client_id][1][0].to_bytes(self.num_bytes, sys.byteorder)
                        bytes += self.shares_of_arithmetic_z_shares[client_id][1][1].to_bytes(self.num_bytes, sys.byteorder)
                        self.shares_of_arithmetic_z_shares[client_id][0] = (self.shares_of_arithmetic_z_shares[client_id][0][0],self.shares_of_arithmetic_z_shares[client_id][0][2])
                        self.shares_of_arithmetic_z_shares[client_id][2] = (self.shares_of_arithmetic_z_shares[client_id][2][0],self.shares_of_arithmetic_z_shares[client_id][2][2])
                    else:
                        bytes += self.shares_of_arithmetic_z_shares[client_id][0][0].to_bytes(self.num_bytes, sys.byteorder)
                        bytes += self.shares_of_arithmetic_z_shares[client_id][0][1].to_bytes(self.num_bytes, sys.byteorder)
                        self.shares_of_arithmetic_z_shares[client_id][1] = (self.shares_of_arithmetic_z_shares[client_id][1][2],self.shares_of_arithmetic_z_shares[client_id][1][1])
                        self.shares_of_arithmetic_z_shares[client_id][2] = (self.shares_of_arithmetic_z_shares[client_id][2][2],self.shares_of_arithmetic_z_shares[client_id][2][1])

                hash_obj = hashes.Hash(hashes.SHA256())
                hash_obj.update(bytes)
                hash = hash_obj.finalize()
                if hash == self.received_hash_of_z_shares:
                    self.logger.info('the received boolean shares of z shares are consistent.')
                else:
                    self.logger.error('the received boolean shares of z shares are inconsistent!')

                # extract bits of the shares
                for client_id in self.shares_of_arithmetic_z_shares.keys():
                    for i in range(3):
                        bits_i_1 = int_to_twos_complement(self.shares_of_arithmetic_z_shares[client_id][i][0], self.ring_size, order_reversed=True)
                        bits_i_2 = int_to_twos_complement(self.shares_of_arithmetic_z_shares[client_id][i][1], self.ring_size, order_reversed=True)
                        self.shares_of_arithmetic_z_shares[client_id][i] = (bits_i_1,bits_i_2)
                    
                    # self.logger.debug('boolean shares of z shares of client %s:\n%s',client_id,self.shares_of_arithmetic_z_shares[client_id])

                # execute boolean addition 
                # firstly, compute [z_0]^B = [z_12]^B+[z_13]^B
                # compute intermediate results
                for client_id in self.shares_of_arithmetic_z_shares.keys():
                    self.one_server_shares_1[client_id] = ['','']
                    # check the length of Boolean shares 
                    for i in range(3):
                        assert len(self.shares_of_arithmetic_z_shares[client_id][i][0]) == self.ring_size
                        assert len(self.shares_of_arithmetic_z_shares[client_id][i][1]) == self.ring_size
                    for i in range(self.ring_size):
                        share1 = int(self.shares_of_arithmetic_z_shares[client_id][0][0][i]) & int(self.shares_of_arithmetic_z_shares[client_id][1][1][i])
                        share2 = int(self.shares_of_arithmetic_z_shares[client_id][0][1][i]) & int(self.shares_of_arithmetic_z_shares[client_id][1][0][i])
                        if self.id == 1:
                            self.one_server_shares_1[client_id][0] = self.one_server_shares_1[client_id][0] + str(share1 ^ share2)
                        else:
                            self.one_server_shares_1[client_id][1] = self.one_server_shares_1[client_id][1] + str(share1 ^ share2)

                # send the intermediate results
                if self.id == 1:
                    address = ('localhost',self.peers['2'])
                    request = "SERVER-1-INTERMEDIAT"
                elif self.id == 2:
                    address = ('localhost',self.peers['3'])
                    request = "SERVER-2-INTERMEDIAT"
                else:
                    address = ('localhost',self.peers['1'])
                    request = "SERVER-3-INTERMEDIAT"
                socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                socket_obj.connect(address)
                socket_obj.send(request.encode())
                for client_id in self.one_server_shares_1.keys():
                    socket_obj.send(client_id.encode())   
                    if self.id == 1:             
                        socket_obj.send(self.one_server_shares_1[client_id][0].encode())
                    else:
                        socket_obj.send(self.one_server_shares_1[client_id][1].encode())

            if self.is_receive_one_server_shares_1_done == True:
                self.is_receive_one_server_shares_1_done = False 
                for client_id in self.shares_of_arithmetic_z_shares.keys():
                    self.carry_bits_1[client_id] = '0'
                    self.two_server_shares_1[client_id] = ['','']
                    for i in range(self.ring_size):
                        share1 = int(self.shares_of_arithmetic_z_shares[client_id][0][0][i]) & int(self.shares_of_arithmetic_z_shares[client_id][1][0][i])
                        share2 = int(self.shares_of_arithmetic_z_shares[client_id][0][1][i]) & int(self.shares_of_arithmetic_z_shares[client_id][1][1][i])
                        share3 = (int(self.shares_of_arithmetic_z_shares[client_id][0][0][i]) ^ int(self.shares_of_arithmetic_z_shares[client_id][1][0][i])) & int(self.carry_bits_1[client_id][i])
                        share4 = (int(self.shares_of_arithmetic_z_shares[client_id][0][1][i]) ^ int(self.shares_of_arithmetic_z_shares[client_id][1][1][i])) & int(self.carry_bits_1[client_id][i])
                        self.two_server_shares_1[0] = self.two_server_shares_1[0] + str(share1 ^ share3)
                        self.two_server_shares_1[1] = self.two_server_shares_1[1] + str(share2 ^ share4)

                        self.carry_bits_1[client_id] = self.carry_bits_1[client_id] + str()
                """


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
            view_of_inputs = socket_obj.recv(32)
            if view_of_inputs == self.views_to_comp['inputs']:
                self.logger.info('the view of inputs is consistent.')
            else:
                self.logger.error('the view of inputs is inconsistent!')
            self.is_input_batchcheck_done = True

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
                socket_obj.send(self.views_to_send['inputs'])
            else:
                request = socket_obj.recv(20).decode()
                assert request == "SERVER-2-BATCHCHECK-"
                view_of_inputs = socket_obj.recv(32)
                if view_of_inputs == self.views_to_comp['inputs']:
                    self.logger.info('the view of inputs is consistent.')
                else:
                    self.logger.error('the view of inputs is inconsistent!')
                self.is_input_batchcheck_done = True

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

    def boolean2arithmetic_conversion(self):
        # ctr12_bytes = b''
        # ctr13_bytes = b''
        # ctr23_bytes = b''
        # shares_to_send = {}
        for client_id in self.shares.keys():
            # if client_id not in shares_to_send.keys(): shares_to_send[client_id] = {}
            if client_id not in self.arithmetic_shares_for_conversion.keys(): self.arithmetic_shares_for_conversion[client_id] = []
            index = 0
            for i in range(self.data_dimension):
                for j in range(self.ring_size):
                    self.arithmetic_shares_for_conversion[client_id].append([])
                    if self.id == 1:
                        # if 'to_S2' not in shares_to_send[client_id].keys(): shares_to_send[client_id]['to_S2'] = []
                        # if 'to_S3' not in shares_to_send[client_id].keys(): shares_to_send[client_id]['to_S3'] = []
                        # generate shares of x_i_12
                        # ctr12_bytes = self.PRF_counters[0].to_bytes(8, sys.byteorder)
                        # hmac_obj = hmac.HMAC(self.keys[0], hashes.SHA256())
                        # hmac_obj.update(ctr12_bytes)
                        # x_i_12_12 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask 
                        # self.PRF_counters[0] += 1

                        # x_i_12_13 = (x_i_12_12 + 1) & self.mask
                        # ctr12_bytes = self.PRF_counters[0].to_bytes(8, sys.byteorder)
                        # hmac_obj = hmac.HMAC(self.keys[0], hashes.SHA256())
                        # hmac_obj.update(ctr12_bytes)
                        # x_i_12_13 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        # self.PRF_counters[0] += 1

                        x_i_12_13 = x_i_12_23 = 0
                        x_i_12_12 = int(self.shares[client_id][i][0][j])
                        # x_i_12_23 = (int(self.shares[client_id][i][0][j]) - x_i_12_12 - x_i_12_13) & self.mask
                        # shares_to_S3 = (x_i_12_23, x_i_12_13)
                        # shares_to_send[client_id]['to_S3'].append(shares_to_S3)
                        self.arithmetic_shares_for_conversion[client_id][index].append((x_i_12_12,x_i_12_13))

                        # generate shares of x_i_13
                        # ctr13_bytes = self.PRF_counters[1].to_bytes(8, sys.byteorder)
                        # hmac_obj = hmac.HMAC(self.keys[1], hashes.SHA256())
                        # hmac_obj.update(ctr13_bytes)
                        # x_i_13_12 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        # self.PRF_counters[1] += 1

                        # x_i_13_13 = (x_i_13_12 + 1) & self.mask
                        # ctr13_bytes = self.PRF_counters[1].to_bytes(8, sys.byteorder)
                        # hmac_obj = hmac.HMAC(self.keys[1], hashes.SHA256())
                        # hmac_obj.update(ctr13_bytes)
                        # x_i_13_13 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        # self.PRF_counters[1] += 1

                        x_i_13_12 = x_i_13_23 = 0
                        x_i_13_13 = int(self.shares[client_id][i][1][j])
                        # x_i_13_23 = (int(self.shares[client_id][i][1][j]) - x_i_13_12 - x_i_13_13) & self.mask
                        # shares_to_S2 = (x_i_13_12,x_i_13_23)
                        # shares_to_send[client_id]['to_S2'].append(shares_to_S2)
                        self.arithmetic_shares_for_conversion[client_id][index].append((x_i_13_12,x_i_13_13))
                        self.arithmetic_shares_for_conversion[client_id][index].append((0,0))
                        index += 1

                    elif self.id == 2:
                        # if 'to_S1' not in shares_to_send[client_id].keys(): shares_to_send[client_id]['to_S1'] = []
                        # if 'to_S3' not in shares_to_send[client_id].keys(): shares_to_send[client_id]['to_S3'] = []
                        # generate shares of x_i_12
                        # ctr12_bytes = self.PRF_counters[0].to_bytes(8, sys.byteorder)
                        # hmac_obj = hmac.HMAC(self.keys[0], hashes.SHA256())
                        # hmac_obj.update(ctr12_bytes)
                        # x_i_12_12 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        # self.PRF_counters[0] += 1

                        # x_i_12_13 = (x_i_12_12 + 1) & self.mask
                        # ctr12_bytes = self.PRF_counters[0].to_bytes(8, sys.byteorder)
                        # hmac_obj = hmac.HMAC(self.keys[0], hashes.SHA256())
                        # hmac_obj.update(ctr12_bytes)
                        # x_i_12_13 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        # self.PRF_counters[0] += 1

                        x_i_12_13 = x_i_12_23 = 0
                        x_i_12_12 = int(self.shares[client_id][i][0][j])
                        # x_i_12_23 = (int(self.shares[client_id][i][0][j]) - x_i_12_12 - x_i_12_13) & self.mask
                        # shares_to_S3 = (x_i_12_23,x_i_12_13)
                        # shares_to_send[client_id]['to_S3'].append(shares_to_S3)
                        self.arithmetic_shares_for_conversion[client_id][index].append((x_i_12_12,x_i_12_23))

                        # generate shares of x_i_23
                        # ctr23_bytes = self.PRF_counters[1].to_bytes(8, sys.byteorder)
                        # hmac_obj = hmac.HMAC(self.keys[1], hashes.SHA256())
                        # hmac_obj.update(ctr23_bytes)
                        # x_i_23_12 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask                    
                        # self.PRF_counters[1] += 1

                        # x_i_23_13 = (x_i_23_12 + 1) & self.mask
                        # ctr23_bytes = self.PRF_counters[1].to_bytes(8, sys.byteorder)
                        # hmac_obj = hmac.HMAC(self.keys[1], hashes.SHA256())
                        # hmac_obj.update(ctr23_bytes)
                        # x_i_23_13 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        # self.PRF_counters[1] += 1

                        x_i_23_12 = x_i_23_13 = 0
                        x_i_23_23 = int(self.shares[client_id][i][1][j])
                        # x_i_23_23 = (int(self.shares[client_id][i][1][j]) - x_i_23_12 - x_i_23_13) & self.mask
                        # shares_to_S1 = (x_i_23_12,x_i_23_13)
                        # shares_to_send[client_id]['to_S1'].append(shares_to_S1)
                        self.arithmetic_shares_for_conversion[client_id][index].append((0,0))
                        self.arithmetic_shares_for_conversion[client_id][index].append((x_i_23_12,x_i_23_23))

                        index += 1

                    else:
                        # if 'to_S1' not in shares_to_send[client_id].keys(): shares_to_send[client_id]['to_S1'] = []
                        # if 'to_S2' not in shares_to_send[client_id].keys(): shares_to_send[client_id]['to_S2'] = []
                        # generate shares of x_i_23
                        # ctr23_bytes = self.PRF_counters[0].to_bytes(8, sys.byteorder)
                        # hmac_obj = hmac.HMAC(self.keys[0], hashes.SHA256())
                        # hmac_obj.update(ctr23_bytes)
                        # x_i_23_12 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask 
                        # self.PRF_counters[0] += 1

                        # x_i_23_13 = (x_i_23_12 + 1) & self.mask
                        # ctr23_bytes = self.PRF_counters[0].to_bytes(8, sys.byteorder)
                        # hmac_obj = hmac.HMAC(self.keys[0], hashes.SHA256())
                        # hmac_obj.update(ctr23_bytes)
                        # x_i_23_13 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask 
                        # self.PRF_counters[0] += 1

                        x_i_23_12 = x_i_23_13 = 0
                        x_i_23_23 = int(self.shares[client_id][i][0][j])
                        # x_i_23_23 = (int(self.shares[client_id][i][0][j]) - x_i_23_12 - x_i_23_13) & self.mask
                        # shares_to_S1 = (x_i_23_12,x_i_23_13)
                        # shares_to_send[client_id]['to_S1'].append(shares_to_S1)
                        # self.arithmetic_shares_for_conversion[client_id][index].append((x_i_23_23,x_i_23_13))

                        # generate shares of x_i_13
                        # ctr13_bytes = self.PRF_counters[1].to_bytes(8, sys.byteorder)
                        # hmac_obj = hmac.HMAC(self.keys[1], hashes.SHA256())
                        # hmac_obj.update(ctr13_bytes)
                        # x_i_13_12 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        # self.PRF_counters[1] += 1

                        # x_i_13_13 = (x_i_13_12 + 1) & self.mask
                        # ctr13_bytes = self.PRF_counters[1].to_bytes(8, sys.byteorder)
                        # hmac_obj = hmac.HMAC(self.keys[1], hashes.SHA256())
                        # hmac_obj.update(ctr13_bytes)
                        # x_i_13_13 = int.from_bytes(hmac_obj.finalize(), sys.byteorder) & self.mask
                        # self.PRF_counters[1] += 1

                        x_i_13_12 = x_i_13_23 = 0
                        x_i_13_13 = int(self.shares[client_id][i][1][j])
                        # x_i_13_23 = (int(self.shares[client_id][i][1][j]) - x_i_13_12 - x_i_13_13) & self.mask
                        # shares_to_S2 = (x_i_13_12,x_i_13_23)
                        # shares_to_send[client_id]['to_S2'].append(shares_to_S2)
                        self.arithmetic_shares_for_conversion[client_id][index].append((0,0))
                        self.arithmetic_shares_for_conversion[client_id][index].append((x_i_13_23,x_i_13_13))
                        self.arithmetic_shares_for_conversion[client_id][index].append((x_i_23_23,x_i_23_13))
                        index += 1
        self.is_share_transmission_for_conversion_done = True
        # send the shares 
        # for client_id in shares_to_send.keys():
        #     if self.id == 1:
        #         # send to server 2
        #         s2_address = ('localhost', self.peers['2'])
        #         socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #         socket_obj.connect(s2_address)
        #         request = 'SERVER-1-CONVERSION-'
        #         socket_obj.send(request.encode())
        #         socket_obj.send(client_id.encode())
        #         index = 0
        #         for i in range(self.data_dimension):
        #             for j in range(self.ring_size):
        #                 for k in range(2):
        #                     share_bytes = shares_to_send[client_id]['to_S2'][index][k].to_bytes(self.num_bytes, sys.byteorder)
        #                     socket_obj.send(share_bytes)
        #                 index += 1
        #         socket_obj.close()
        #         # send to server 3 
        #         s3_address = ('localhost', self.peers['3'])
        #         socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #         socket_obj.connect(s3_address)
        #         socket_obj.send(request.encode())
        #         socket_obj.send(client_id.encode())
        #         index = 0
        #         for i in range(self.data_dimension):
        #             for j in range(self.ring_size):
        #                 for k in range(2):
        #                     share_bytes = shares_to_send[client_id]['to_S3'][index][k].to_bytes(self.num_bytes, sys.byteorder)
        #                     socket_obj.send(share_bytes)
        #                 index += 1
        #         socket_obj.close()
        #     elif self.id == 2:
        #         # send to server 1
        #         s1_address = ('localhost', self.peers['1'])
        #         socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #         socket_obj.connect(s1_address)
        #         request = 'SERVER-2-CONVERSION-'
        #         socket_obj.send(request.encode())
        #         socket_obj.send(client_id.encode())
        #         index = 0
        #         for i in range(self.data_dimension):
        #             for j in range(self.ring_size):
        #                 for k in range(2):
        #                     share_bytes = shares_to_send[client_id]['to_S1'][index][k].to_bytes(self.num_bytes, sys.byteorder)
        #                     socket_obj.send(share_bytes)
        #                 index += 1
        #         socket_obj.close()
        #         # send to server 3 
        #         s3_address = ('localhost', self.peers['3'])
        #         socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #         socket_obj.connect(s3_address)
        #         socket_obj.send(request.encode())
        #         socket_obj.send(client_id.encode())
        #         index = 0
        #         for i in range(self.data_dimension):
        #             for j in range(self.ring_size):
        #                 for k in range(2):
        #                     share_bytes = shares_to_send[client_id]['to_S3'][index][k].to_bytes(self.num_bytes, sys.byteorder)
        #                     socket_obj.send(share_bytes)
        #                 index += 1
        #         socket_obj.close()
        #     else:
        #         # send to server 1
        #         s1_address = ('localhost', self.peers['1'])
        #         socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #         socket_obj.connect(s1_address)
        #         request = 'SERVER-3-CONVERSION-'
        #         socket_obj.send(request.encode())
        #         socket_obj.send(client_id.encode())
        #         index = 0
        #         for i in range(self.data_dimension):
        #             for j in range(self.ring_size):
        #                 for k in range(2):
        #                     share_bytes = shares_to_send[client_id]['to_S1'][index][k].to_bytes(self.num_bytes, sys.byteorder)
        #                     socket_obj.send(share_bytes)
        #                 index += 1
        #         socket_obj.close()
        #         # send to server 2 
        #         s2_address = ('localhost', self.peers['2'])
        #         socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #         socket_obj.connect(s2_address)
        #         socket_obj.send(request.encode())
        #         socket_obj.send(client_id.encode())
        #         index = 0
        #         for i in range(self.data_dimension):
        #             for j in range(self.ring_size):
        #                 for k in range(2):
        #                     share_bytes = shares_to_send[client_id]['to_S2'][index][k].to_bytes(self.num_bytes, sys.byteorder)
        #                     socket_obj.send(share_bytes)
        #                 index += 1
        #         socket_obj.close()
   
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
        
    def semihonest_multiplication_batch(self, shares : Dict[str, List[List[Tuple[int,int]]]], label : str = 'layer1'):
        for client_id in shares.keys():
            if label == 'layer1':
                self.yis_in_multiplication_protocol_layer1[client_id] = []
            else:
                self.yis_in_multiplication_protocol_layer2[client_id] = []
            # number of iteration: data_dimension x ring_size
            # self.logger.debug('shares of client %s:\n%s',client_id,shares[client_id])
            for i in range(len(shares[client_id])): 
                zero_share = self.zero_sharing()
                y_i = 0 
                y_i += zero_share
                if self.id == 1:
                    y_i = (y_i + shares[client_id][i][0][0] * shares[client_id][i][1][0] + \
                            shares[client_id][i][0][0] * shares[client_id][i][1][1] + \
                            shares[client_id][i][0][1] * shares[client_id][i][1][0]) & self.mask
                    if label == 'layer1':
                        self.yis_in_multiplication_protocol_layer1[client_id].append([y_i, 0])
                    else:
                        self.yis_in_multiplication_protocol_layer2[client_id].append([y_i, 0])
                else:
                    y_i = (y_i + shares[client_id][i][0][1] * shares[client_id][i][1][1] + \
                            shares[client_id][i][0][0] * shares[client_id][i][1][1] + \
                            shares[client_id][i][0][1] * shares[client_id][i][1][0]) & self.mask
                    if label == 'layer1':
                        self.yis_in_multiplication_protocol_layer1[client_id].append([0, y_i])
                    else:
                        self.yis_in_multiplication_protocol_layer2[client_id].append([0, y_i])
        if self.id == 1:
            s2_address = ('localhost',self.peers['2'])
            socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_obj.connect(s2_address)
            if label == 'layer1': request = "SERVER-1-MULTIBATCH1"
            else:                 request = "SERVER-1-MULTIBATCH2"
            socket_obj.send(request.encode())
            if label == 'layer1':
                for client_id in self.yis_in_multiplication_protocol_layer1.keys():
                    socket_obj.send(client_id.encode())
                    for i in range(len(self.yis_in_multiplication_protocol_layer1[client_id])):
                        socket_obj.send(self.yis_in_multiplication_protocol_layer1[client_id][i][0].to_bytes(self.num_bytes, sys.byteorder))
            else:
                for client_id in self.yis_in_multiplication_protocol_layer2.keys():
                    socket_obj.send(client_id.encode())
                    for i in range(len(self.yis_in_multiplication_protocol_layer2[client_id])):
                        socket_obj.send(self.yis_in_multiplication_protocol_layer2[client_id][i][0].to_bytes(self.num_bytes, sys.byteorder))
        elif self.id == 2:
            s3_address = ('localhost',self.peers['3'])
            socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_obj.connect(s3_address)
            if label == 'layer1':   request = "SERVER-2-MULTIBATCH1"
            else:                   request = "SERVER-2-MULTIBATCH2"
            socket_obj.send(request.encode())
            if label == 'layer1':
                for client_id in self.yis_in_multiplication_protocol_layer1.keys():
                    socket_obj.send(client_id.encode())
                    for i in range(len(self.yis_in_multiplication_protocol_layer1[client_id])):
                        socket_obj.send(self.yis_in_multiplication_protocol_layer1[client_id][i][1].to_bytes(self.num_bytes, sys.byteorder))
            else:
                for client_id in self.yis_in_multiplication_protocol_layer2.keys():
                    socket_obj.send(client_id.encode())
                    for i in range(len(self.yis_in_multiplication_protocol_layer2[client_id])):
                        socket_obj.send(self.yis_in_multiplication_protocol_layer2[client_id][i][1].to_bytes(self.num_bytes, sys.byteorder))
        else:
            s1_address = ('localhost',self.peers['1'])                    
            socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_obj.connect(s1_address)
            if label == 'layer1':   request = "SERVER-3-MULTIBATCH1"
            else:                   request = "SERVER-3-MULTIBATCH2"
            socket_obj.send(request.encode())
            if label == 'layer1':
                for client_id in self.yis_in_multiplication_protocol_layer1.keys():
                    socket_obj.send(client_id.encode())
                    for i in range(len(self.yis_in_multiplication_protocol_layer1[client_id])):
                        socket_obj.send(self.yis_in_multiplication_protocol_layer1[client_id][i][1].to_bytes(self.num_bytes, sys.byteorder))
            else:
                for client_id in self.yis_in_multiplication_protocol_layer2.keys():
                    socket_obj.send(client_id.encode())
                    for i in range(len(self.yis_in_multiplication_protocol_layer2[client_id])):
                        socket_obj.send(self.yis_in_multiplication_protocol_layer2[client_id][i][1].to_bytes(self.num_bytes, sys.byteorder))
        if label == 'layer1':   self.is_layer1_multiplication_done = True
        else:                   self.is_layer2_multiplication_done = True

    def compute_sharings_of_sigmas(self):
        self.logger.info('computing sharings of sigmas...')
        for client_id in self.arithmetic_shares_for_conversion.keys():
            self.shares_of_sigmas[client_id] = []
            for i in range(len(self.arithmetic_shares_for_conversion[client_id])):
                share1 = (self.arithmetic_shares_for_conversion[client_id][i][0][0] + \
                          self.arithmetic_shares_for_conversion[client_id][i][1][0]) & self.mask
                share2 = (self.arithmetic_shares_for_conversion[client_id][i][0][1] + \
                          self.arithmetic_shares_for_conversion[client_id][i][1][1]) & self.mask
                share3 = (2 * self.yis_in_multiplication_protocol_layer1[client_id][i][0]) & self.mask
                share4 = (2 * self.yis_in_multiplication_protocol_layer1[client_id][i][1]) & self.mask

                self.shares_of_sigmas[client_id].append(((share1 - share3) & self.mask, \
                                                        (share2 - share4) & self.mask))

    def compute_sharings_of_xs(self):
        self.logger.info('computing sharings of xs...')
        for client_id in self.arithmetic_shares_for_conversion.keys():
            self.shares_of_xs[client_id] = []
            for i in range(len(self.arithmetic_shares_for_conversion[client_id])):
                share1 = (self.shares_of_sigmas[client_id][i][0] + \
                          self.arithmetic_shares_for_conversion[client_id][i][2][0]) & self.mask
                share2 = (self.shares_of_sigmas[client_id][i][1] + \
                          self.arithmetic_shares_for_conversion[client_id][i][2][1]) & self.mask
                share3 = (2 * self.yis_in_multiplication_protocol_layer2[client_id][i][0]) & self.mask 
                share4 = (2 * self.yis_in_multiplication_protocol_layer2[client_id][i][1]) & self.mask

                self.shares_of_xs[client_id].append(((share1 - share3) & self.mask, \
                                                    (share2 - share4) & self.mask))

    def compute_final_converted_arithmetic_shares(self):
        self.logger.info('computing the final converted arithmetic shares...')
        for client_id in self.shares_of_xs.keys():
            self.final_converted_arithmetic_shares[client_id] = []
            assert len(self.shares_of_xs[client_id]) == (self.data_dimension * self.ring_size)
            for i in range(self.data_dimension):
                share1 = 0 
                share2 = 0
                for j in range(self.ring_size):
                    share1 = (share1 + (pow(2, j) * self.shares_of_xs[client_id][i*self.ring_size+j][0])) & self.mask
                    share2 = (share2 + (pow(2, j) * self.shares_of_xs[client_id][i*self.ring_size+j][1])) & self.mask
                self.final_converted_arithmetic_shares[client_id].append((share1, share2))        

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
            self.server.num_bytes = math.ceil(self.server.ring_size / 8)
            # compute the mask 
            self.server.mask = pow(2, self.server.ring_size) - 1
            self.logger.debug('received ring size: %s',self.server.ring_size)
            self.logger.debug('number of bytes: %s',self.server.num_bytes)
            if self.server.id == 1:
                # receive data dimension 
                bytes_data_dimension = self.request.recv(3)
                self.server.data_dimension = int.from_bytes(bytes_data_dimension, sys.byteorder)
                self.logger.debug('received data dimension: %s',self.server.data_dimension)
                # receive byte length of each dimension 
                bytes_length = self.request.recv(4)
                length = int.from_bytes(bytes_length, sys.byteorder)
                self.logger.debug('received length of seeds: %s',length)
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
                    x_i_12 = extract_boolean_shares(x_i_12, self.server.ring_size)
                    random.seed(s_1)
                    s_1 += 1
                    x_i_13 = random.randint(0, pow(2, self.server.ring_size)-1)
                    x_i_13 = extract_boolean_shares(x_i_13, self.server.ring_size)
                    self.server.shares[client_id].append((x_i_12,x_i_13))

            else:
                self.server.data_dimension = num_shares - 1
                self.logger.debug('received data dimension: %s',self.server.data_dimension)
                # receive the length of seed 
                bytes_length = self.request.recv(4)
                length = int.from_bytes(bytes_length, sys.byteorder)
                self.logger.debug('received length of the seed: %s', length)
                # receive the seed
                bytes_seed = self.request.recv(length)
                self.server.client_data[client_id].append(int.from_bytes(bytes_seed, sys.byteorder))
                # receive the length of each share 
                bytes_length = self.request.recv(4)
                length = int.from_bytes(bytes_length, sys.byteorder)
                self.logger.debug('received length of each share: %s', length)
                # receive shares 
                seed = int.from_bytes(bytes_seed, sys.byteorder)
                for i in range(self.server.data_dimension):
                    bytes = self.request.recv(length)
                    shares_dimension_i = bytes.decode()
                    self.server.client_data[client_id].append(shares_dimension_i)
                    if self.server.id == 2: # the seed is s_0
                        random.seed(seed)
                        seed += 1
                        x_i_12 = random.randint(0, pow(2, self.server.ring_size)-1)
                        x_i_12 = extract_boolean_shares(x_i_12, self.server.ring_size)
                        self.server.shares[client_id].append((x_i_12,shares_dimension_i))
                    else: # the seed is s_1
                        random.seed(seed)
                        seed += 1
                        x_i_13 = random.randint(0, pow(2, self.server.ring_size)-1)
                        x_i_13 = extract_boolean_shares(x_i_13, self.server.ring_size)
                        self.server.shares[client_id].append((shares_dimension_i,x_i_13))

            # receive shares of beaver multiplication triples 
            ais, cis = [], []
            for i in range(self.server.data_dimension):
                ai_1 = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                ai_2 = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                ci_1 = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                ci_2 = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                ais.append((ai_1,ai_2))
                cis.append((ci_1,ci_2))
            self.server.shares_of_beaver_triples_ais[client_id] = ais
            self.server.shares_of_beaver_triples_cis[client_id] = cis

            # self.logger.debug('received shares of beaver triples from client %s:\nais:\n%s\ncis:\n%s',client_id,ais,cis)

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
                self.server.is_uploading_done = True
            
                # when the uploading is done, compute the view of received shares for batch check 
                self.logger.info('computing the view of inputs...')
                str_send = ''
                str_comp = ''
                for client_id in self.server.shares.keys():
                    for j in range(self.server.data_dimension):
                        if self.server.id == 1:
                            str_send = str_send + self.server.shares[client_id][j][0]
                            str_comp = str_comp + self.server.shares[client_id][j][1]
                        else:
                            str_send = str_send + self.server.shares[client_id][j][1]
                            str_comp = str_comp + self.server.shares[client_id][j][0]
                hash_obj = hashes.Hash(hashes.SHA256())
                hash_obj.update(str_send.encode())
                hash_send = hash_obj.finalize()
                self.server.views_to_send['inputs'] = hash_send
                hash_obj = hashes.Hash(hashes.SHA256())
                hash_obj.update(str_comp.encode())
                hash_comp = hash_obj.finalize()
                self.server.views_to_comp['inputs'] = hash_comp
            
        elif request.decode() == REQUESTS[1]: # Server 2 requests for shakehanding
            self.logger.info("received request: SERVER-2-SHAKEHAND--")
            response = "check"
            self.request.send(response.encode())
            self.logger.info('shakehand with peer server 2 done.')
            # start to batch-check the inputs 
            request = "SERVER-1-BATCHCHECK-"
            self.request.send(request.encode())
            self.request.send(self.server.views_to_send['inputs'])

        elif request.decode() == REQUESTS[2]: # Server 3 requests for shakehanding
            self.logger.info("received request: SERVER-3-SHAKEHAND--")
            response = "check"
            self.request.send(response.encode())
            self.logger.info('shakehand with peer server 3 done.')
            if self.server.id == 2: # send request for batch-check to server 3
                request = "SERVER-2-BATCHCHECK-"
                self.request.send(request.encode())
                self.request.send(self.server.views_to_send['inputs'])
            else:
                request = self.request.recv(20)
                assert request.decode() == "SERVER-3-BATCHCHECK-"
                view_of_inputs = self.request.recv(32)
                if view_of_inputs == self.server.views_to_comp['inputs']:
                    self.logger.info('the view of inputs is consistent.')
                else:
                    self.logger.error('the view of inputs is inconsistent!')                
                self.server.is_input_batchcheck_done = True

        elif request.decode() == REQUESTS[6]: # Server 1 requests for share conversion 
            self.logger.info("received request: SERVER-1-CONVERSION-")
            if 'from_s1' not in self.server.shares_received_for_conversion.keys():
                self.server.shares_received_for_conversion['from_s1'] = {}
            client_id = self.request.recv(4).decode()
            if client_id not in self.server.shares_received_for_conversion['from_s1'].keys(): 
                self.server.shares_received_for_conversion['from_s1'][client_id] = []
            for i in range(self.server.data_dimension):
                for j in range(self.server.ring_size):
                    shares_bit_j = []
                    for k in range(2):
                        bytes = self.request.recv(self.server.num_bytes)
                        share = int.from_bytes(bytes, sys.byteorder)
                        shares_bit_j.append(share)
                    self.server.shares_received_for_conversion['from_s1'][client_id].append(shares_bit_j)
            self.logger.info('receive shares for conversion done.')
            self.server.num_shares_for_conversion_received += 1
            # check whether all required shares from other two servers are received
            if self.server.num_shares_for_conversion_received == (2 * self.server.num_clients):  
                # if they are all received, check consistency 
                consistency_flag = True
                for client_id in self.server.shares_received_for_conversion['from_s1'].keys():
                    if self.server.id == 2: # current server is server 2
                        if self.server.shares_received_for_conversion['from_s1'] == self.server.shares_received_for_conversion['from_s3']:
                            self.logger.info('shares for conversion for client %s is consistent.',client_id)
                        else:
                            self.logger.error('shares for conversion for client %s is inconsistent!',client_id)
                            consistency_flag = False

                    else: # current server is server 3
                        if self.server.shares_received_for_conversion['from_s1'] == self.server.shares_received_for_conversion['from_s2']:
                            self.logger.info('shares for conversion for client %s is consistent.',client_id)
                        else:
                            self.logger.error('shares for conversion for client %s is inconsistent!',client_id)
                            consistency_flag = False

                if consistency_flag == True:
                    self.logger.info('the shares for conversion from other two servers are consistent.')
                    if self.server.id == 2:
                        # if all the shares are consistent, reserve the ones from server 1 and delete the other ones
                        self.logger.info('recombine the arithmetic shares...')
                        del self.server.shares_received_for_conversion['from_s3']
                        for client_id in self.server.shares_received_for_conversion['from_s1'].keys():
                            assert len(self.server.shares_received_for_conversion['from_s1'][client_id]) == len(self.server.arithmetic_shares_for_conversion[client_id])
                            num_shares = len(self.server.arithmetic_shares_for_conversion[client_id])
                            for i in range(num_shares):
                                shares_to_insert = (self.server.shares_received_for_conversion['from_s1'][client_id][i][0],self.server.shares_received_for_conversion['from_s1'][client_id][i][1])
                                self.server.arithmetic_shares_for_conversion[client_id][i].append(shares_to_insert)
                                self.server.arithmetic_shares_for_conversion[client_id][i][1], \
                                self.server.arithmetic_shares_for_conversion[client_id][i][2] = \
                                    self.server.arithmetic_shares_for_conversion[client_id][i][2], \
                                    self.server.arithmetic_shares_for_conversion[client_id][i][1]
                                # if i == 0:
                                #     self.logger.debug('the first group of shares:\n%s',self.server.arithmetic_shares_for_conversion[client_id][i])
                                # elif i == len(self.server.arithmetic_shares_for_conversion[client_id]) - 1:
                                #     self.logger.debug('the last group of shares:\n%s',self.server.arithmetic_shares_for_conversion[client_id][i])              
                    else:
                        # if the shares are consistent, reserve the ones from server 2 and delete the other ones
                        del self.server.shares_received_for_conversion['from_s1']
                        self.logger.info('recombine the arithmetic shares...')
                        for client_id in self.server.shares_received_for_conversion['from_s2'].keys():
                            assert len(self.server.shares_received_for_conversion['from_s2'][client_id]) == len(self.server.arithmetic_shares_for_conversion[client_id])
                            num_shares = len(self.server.arithmetic_shares_for_conversion[client_id])
                            for i in range(num_shares):
                                shares_to_insert = (self.server.shares_received_for_conversion['from_s2'][client_id][i][0],self.server.shares_received_for_conversion['from_s2'][client_id][i][1])
                                self.server.arithmetic_shares_for_conversion[client_id][i].append(shares_to_insert)
                                self.server.arithmetic_shares_for_conversion[client_id][i].reverse()
                                # if i == 0:
                                #     self.logger.debug('the first group of shares:\n%s',self.server.arithmetic_shares_for_conversion[client_id][i])
                                # elif i == len(self.server.arithmetic_shares_for_conversion[client_id]) - 1:
                                #     self.logger.debug('the last group of shares:\n%s',self.server.arithmetic_shares_for_conversion[client_id][i])                
                       
                    self.server.is_share_transmission_for_conversion_done = True
                else:
                    self.logger.error('the shares for conversion from other two servers are inconsistent!')

        elif request.decode() == REQUESTS[7]: # Server 2 requests for share conversion 
            self.logger.info("received request: SERVER-2-CONVERSION-")
            if 'from_s2' not in self.server.shares_received_for_conversion.keys():
                self.server.shares_received_for_conversion['from_s2'] = {}
            client_id = self.request.recv(4).decode()
            if client_id not in self.server.shares_received_for_conversion['from_s2'].keys():
                self.server.shares_received_for_conversion['from_s2'][client_id] = []
            for i in range(self.server.data_dimension):
                for j in range(self.server.ring_size):
                    shares_bit_j = []
                    for k in range(2):
                        bytes = self.request.recv(self.server.num_bytes)
                        share = int.from_bytes(bytes, sys.byteorder)
                        shares_bit_j.append(share)
                    self.server.shares_received_for_conversion['from_s2'][client_id].append(shares_bit_j)
            self.logger.info('receive shares for conversion done.')
            self.server.num_shares_for_conversion_received += 1
            # check whether all required shares from other two servers are received
            if self.server.num_shares_for_conversion_received == (2 * self.server.num_clients):
                # check consistency 
                consistency_flag = True
                for client_id in self.server.shares_received_for_conversion['from_s2'].keys():
                    if self.server.id == 1: # current server is server 1
                        if self.server.shares_received_for_conversion['from_s2'] == self.server.shares_received_for_conversion['from_s3']:
                            self.logger.info('shares for conversion for client %s is consistent.',client_id)
                        else:
                            self.logger.error('shares for conversion for client %s is inconsistent!',client_id)
                            consistency_flag = False
                    else: # current server is server 3
                        if self.server.shares_received_for_conversion['from_s2'] == self.server.shares_received_for_conversion['from_s1']:
                            self.logger.info('shares for conversion for client %s is consistent.',client_id)
                        else:
                            self.logger.error('shares for conversion for client %s is inconsistent!',client_id)
                            consistency_flag = False

                if consistency_flag == True:
                    self.logger.info('the shares for conversion from other two servers are consistent.')
                    if self.server.id == 1:
                        # if the shares are consistent, reserve the ones from server 3 and delete the other ones
                        del self.server.shares_received_for_conversion['from_s2']
                        self.logger.info('recombine the arithmetic shares...')
                        for client_id in self.server.shares_received_for_conversion['from_s3'].keys():
                            assert len(self.server.shares_received_for_conversion['from_s3'][client_id]) == len(self.server.arithmetic_shares_for_conversion[client_id])
                            num_shares = len(self.server.arithmetic_shares_for_conversion[client_id])
                            for i in range(len(self.server.arithmetic_shares_for_conversion[client_id])):
                                shares_to_insert = (self.server.shares_received_for_conversion['from_s3'][client_id][i][0],self.server.shares_received_for_conversion['from_s3'][client_id][i][1])
                                self.server.arithmetic_shares_for_conversion[client_id][i].append(shares_to_insert)
                                # if i == 0:
                                #     self.logger.debug('the first group of shares:\n%s',self.server.arithmetic_shares_for_conversion[client_id][i])
                                # elif i == len(self.server.arithmetic_shares_for_conversion[client_id]) - 1:
                                #     self.logger.debug('the last group of shares:\n%s',self.server.arithmetic_shares_for_conversion[client_id][i])
                    else:
                        # if the shares are consistent, reserve the ones from server 2 and delete the other ones 
                        del self.server.shares_received_for_conversion['from_s1']
                        self.logger.info('recombine the arithmetic shares...')
                        for client_id in self.server.shares_received_for_conversion['from_s2'].keys():
                            assert len(self.server.shares_received_for_conversion['from_s2'][client_id]) == len(self.server.arithmetic_shares_for_conversion[client_id])
                            num_shares = len(self.server.arithmetic_shares_for_conversion[client_id])
                            for i in range(len(self.server.arithmetic_shares_for_conversion[client_id])):
                                shares_to_insert = (self.server.shares_received_for_conversion['from_s2'][client_id][i][0],self.server.shares_received_for_conversion['from_s2'][client_id][i][1])
                                self.server.arithmetic_shares_for_conversion[client_id][i].append(shares_to_insert)
                                self.server.arithmetic_shares_for_conversion[client_id][i].reverse()
                                # if i == 0:
                                #     self.logger.debug('the first group of shares:\n%s',self.server.arithmetic_shares_for_conversion[client_id][i])
                                # elif i == len(self.server.arithmetic_shares_for_conversion[client_id]) - 1:
                                #     self.logger.debug('the last group of shares:\n%s',self.server.arithmetic_shares_for_conversion[client_id][i])

                    self.server.is_share_transmission_for_conversion_done = True
                
                else:
                    self.logger.error('the shares for conversion from other two servers are inconsistent!')

        elif request.decode() == REQUESTS[8]: # Server 3 requests for share conversion 
            self.logger.info("received request: SERVER-3-CONVERSION-")
            if 'from_s3' not in self.server.shares_received_for_conversion.keys():
                self.server.shares_received_for_conversion['from_s3'] = {}
            client_id = self.request.recv(4).decode()
            if client_id not in self.server.shares_received_for_conversion['from_s3'].keys():
                self.server.shares_received_for_conversion['from_s3'][client_id] = []
            for i in range(self.server.data_dimension):
                for j in range(self.server.ring_size):
                    shares_bit_j = []
                    for k in range(2):
                        bytes = self.request.recv(self.server.num_bytes)
                        share = int.from_bytes(bytes, sys.byteorder)
                        shares_bit_j.append(share)
                    self.server.shares_received_for_conversion['from_s3'][client_id].append(shares_bit_j)
            self.logger.info('receive shares for conversion done.')
            self.server.num_shares_for_conversion_received += 1
            # check whether all required shares from other two servers are received
            if self.server.num_shares_for_conversion_received == (2 * self.server.num_clients):
                # check consistency 
                consistency_flag = True
                for client_id in self.server.shares_received_for_conversion['from_s3'].keys():
                    if self.server.id == 1: # current server is server 1
                        if self.server.shares_received_for_conversion['from_s3'] == self.server.shares_received_for_conversion['from_s2']:
                            self.logger.info('shares for conversion for client %s is consistent.',client_id)
                        else:
                            self.logger.error('shares for conversion for client %s is inconsistent!',client_id)
                            consistency_flag = False
                    else: # current server is server 2
                        if self.server.shares_received_for_conversion['from_s3'] == self.server.shares_received_for_conversion['from_s1']:
                            self.logger.info('shares for conversion for client %s is consistent.',client_id)
                        else:
                            self.logger.error('shares for conversion for client %s is inconsistent!',client_id)
                            consistency_flag = False

                if consistency_flag == True:
                    self.logger.info('the shares for conversion from other two servers are consistent.')
                    if self.server.id == 1:
                        # if the shares are consistent, reserve the ones from server 3 and delete the other ones
                        del self.server.shares_received_for_conversion['from_s2']
                        self.logger.info('recombine the arithmetic shares...')
                        for client_id in self.server.shares_received_for_conversion['from_s3'].keys():
                            assert len(self.server.shares_received_for_conversion['from_s3'][client_id]) == len(self.server.arithmetic_shares_for_conversion[client_id])
                            num_shares = len(self.server.arithmetic_shares_for_conversion[client_id])
                            for i in range(len(self.server.arithmetic_shares_for_conversion[client_id])):
                                shares_to_insert = (self.server.shares_received_for_conversion['from_s3'][client_id][i][0],self.server.shares_received_for_conversion['from_s3'][client_id][i][1])
                                self.server.arithmetic_shares_for_conversion[client_id][i].append(shares_to_insert)
                                # if i == 0:
                                #     self.logger.debug('the first group of shares:\n%s',self.server.arithmetic_shares_for_conversion[client_id][i])
                                # elif i == len(self.server.arithmetic_shares_for_conversion[client_id]) - 1:
                                #     self.logger.debug('the last group of shares:\n%s',self.server.arithmetic_shares_for_conversion[client_id][i])
                    else:
                        # if the shares are consistent, reserve the ones from server 1 and delete the other ones
                        del self.server.shares_received_for_conversion['from_s3']
                        self.logger.info('recombine the arithmetic shares...')
                        for client_id in self.server.shares_received_for_conversion['from_s1'].keys():
                            assert len(self.server.shares_received_for_conversion['from_s1'][client_id]) == len(self.server.arithmetic_shares_for_conversion[client_id])
                            num_shares = len(self.server.arithmetic_shares_for_conversion[client_id])
                            for i in range(len(self.server.arithmetic_shares_for_conversion[client_id])):
                                shares_to_insert = (self.server.shares_received_for_conversion['from_s1'][client_id][i][0],self.server.shares_received_for_conversion['from_s1'][client_id][i][1])
                                self.server.arithmetic_shares_for_conversion[client_id][i].append(shares_to_insert)
                                self.server.arithmetic_shares_for_conversion[client_id][i][1], \
                                self.server.arithmetic_shares_for_conversion[client_id][i][2] = \
                                    self.server.arithmetic_shares_for_conversion[client_id][i][2], \
                                    self.server.arithmetic_shares_for_conversion[client_id][i][1]
                                # if i == 0:
                                #     self.logger.debug('the first group of shares:\n%s',self.server.arithmetic_shares_for_conversion[client_id][i])
                                # elif i == len(self.server.arithmetic_shares_for_conversion[client_id]) - 1:
                                #     self.logger.debug('the last group of shares:\n%s',self.server.arithmetic_shares_for_conversion[client_id][i])
                          
                    self.server.is_share_transmission_for_conversion_done = True
                
                else:
                    self.logger.error('the shares for conversion from other two servers are inconsistent!')

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

        elif request.decode() == REQUESTS[12]: # Server 1 sends shares in batch multiplication protocol
            self.logger.info('received request: SERVER-1-MULTIBATCH1')
            for i in range(self.server.num_clients):
                client_id = self.request.recv(4).decode()
                self.server.received_yis_in_multiplication_protocol_layer1[client_id] = []
                for j in range(self.server.data_dimension * self.server.ring_size):
                    share = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                    self.server.received_yis_in_multiplication_protocol_layer1[client_id].append(share)
            self.server.is_receive_layer1_multiplication_share_done = True

        elif request.decode() == REQUESTS[13]: # Server 2 sends shares in batch multiplication protocol
            self.logger.info('received request: SERVER-2-MULTIBATCH1')
            for i in range(self.server.num_clients):
                client_id = self.request.recv(4).decode()
                self.server.received_yis_in_multiplication_protocol_layer1[client_id] = []
                for j in range(self.server.data_dimension * self.server.ring_size):
                    share = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                    self.server.received_yis_in_multiplication_protocol_layer1[client_id].append(share)
            self.server.is_receive_layer1_multiplication_share_done = True

        elif request.decode() == REQUESTS[14]: # Server 3 sends shares in batch multiplication protocol
            self.logger.info('received request: SERVER-3-MULTIBATCH1')
            for i in range(self.server.num_clients):
                client_id = self.request.recv(4).decode()
                self.server.received_yis_in_multiplication_protocol_layer1[client_id] = []
                for j in range(self.server.data_dimension * self.server.ring_size):
                    share = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                    self.server.received_yis_in_multiplication_protocol_layer1[client_id].append(share)
            self.server.is_receive_layer1_multiplication_share_done = True

        elif request.decode() == REQUESTS[15]: # Server 1 sends shares again for batch multiplication 
            self.logger.info('received request: SERVER-1-MULTIBATCH2')
            for i in range(self.server.num_clients):
                client_id = self.request.recv(4).decode()
                self.server.received_yis_in_multiplication_protocol_layer2[client_id] = []
                for j in range(self.server.data_dimension * self.server.ring_size):
                    share = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                    self.server.received_yis_in_multiplication_protocol_layer2[client_id].append(share)
            self.server.is_receive_layer2_multiplication_share_done = True

        elif request.decode() == REQUESTS[16]: # Server 2 sends shares again for batch multiplication 
            self.logger.info('received request: SERVER-2-MULTIBATCH2')
            for i in range(self.server.num_clients):
                client_id = self.request.recv(4).decode()
                self.server.received_yis_in_multiplication_protocol_layer2[client_id] = []
                for j in range(self.server.data_dimension * self.server.ring_size):
                    share = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                    self.server.received_yis_in_multiplication_protocol_layer2[client_id].append(share)
            self.server.is_receive_layer2_multiplication_share_done = True

        elif request.decode() == REQUESTS[17]: # Server 3 sends shares again for batch multiplication 
            self.logger.info('received request: SERVER-3-MULTIBATCH2')
            for i in range(self.server.num_clients):
                client_id = self.request.recv(4).decode()
                self.server.received_yis_in_multiplication_protocol_layer2[client_id] = []
                for j in range(self.server.data_dimension * self.server.ring_size):
                    share = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                    self.server.received_yis_in_multiplication_protocol_layer2[client_id].append(share)
            self.server.is_receive_layer2_multiplication_share_done = True

        # Servers send shares of rhois and sigmais for norm check 
        elif request.decode() == REQUESTS[18] or \
            request.decode() == REQUESTS[19] or \
            request.decode() == REQUESTS[20] : 
            if request.decode() == REQUESTS[18]:
                self.logger.info('receive request: SERVER-1-OPENSHARES-')
            elif request.decode() == REQUESTS[19]:
                self.logger.info('receive request: SERVER-2-OPENSHARES-')
            else:
                self.logger.info('receive request: SERVER-3-OPENSHARES-')
            for i in range(self.server.num_clients):
                client_id = self.request.recv(4).decode()
                self.server.received_shares_rhois[client_id] = []
                self.server.received_shares_sigmais[client_id] = []
                for j in range(self.server.data_dimension):
                    share_rho_i = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                    share_sigma_i = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                    self.server.received_shares_rhois[client_id].append(share_rho_i)
                    self.server.received_shares_sigmais[client_id].append(share_sigma_i)
            self.server.is_receive_shares_rhois_sigmais_done = True

        # Servers send views of opened rhois and sigmais  
        elif request.decode() == REQUESTS[21] or \
            request.decode() == REQUESTS[22] or \
            request.decode() == REQUESTS[23] : 
            if request.decode() == REQUESTS[21]:
                self.logger.info('receive request: SERVER-1-CHECKVIEWS-')
            elif request.decode() == REQUESTS[22]:
                self.logger.info('receive request: SERVER-2-CHECKVIEWS-')
            else:
                self.logger.info('receive request: SERVER-3-CHECKVIEWS-')
            for i in range(self.server.num_clients):
                client_id = self.request.recv(4).decode()
                self.server.received_views_of_opened_rhois_sigmais[client_id] = self.request.recv(32)
            self.server.is_receive_views_of_opened_rhois_sigmais_done = True

        # Servers send share of v to open it 
        elif request.decode() == REQUESTS[24] or \
            request.decode() == REQUESTS[25] or \
            request.decode() == REQUESTS[26]:
            if request.decode() == REQUESTS[24]:
                self.logger.info('receive request: SERVER-1-OPENV------')
            elif request.decode() == REQUESTS[25]:
                self.logger.info('receive request: SERVER-2-OPENV------')
            else:
                self.logger.info('receive request: SERVER-3-OPENV------')
            for i in range(self.server.num_clients):
                client_id = self.request.recv(4).decode() 
                share = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
                self.server.received_share_v[client_id] = share
            self.server.is_receive_share_v_done = True

        # Servers send view of vs to check consistency 
        elif request.decode() == REQUESTS[27] or \
            request.decode() == REQUESTS[28] or \
            request.decode() == REQUESTS[29]:
            if request.decode() == REQUESTS[27]:
                self.logger.info('receive request: SERVER-1-CHECKVIEWV-')
            elif request.decode() == REQUESTS[25]:
                self.logger.info('receive request: SERVER-2-CHECKVIEWV-')
            else:
                self.logger.info('receive request: SERVER-3-CHECKVIEWV-')
            self.server.received_view_of_vs = self.request.recv(32)
            self.server.is_receive_view_of_vs_done = True
      
        # # Server 1 sends (z12_23,z12_13) to Server 3
        # elif request.decode() == REQUESTS[30]: 
        #     self.logger.info('receive request: SERVER-1-BOOLEANSHAR')
        #     for i in range(self.server.num_clients):
        #         client_id = self.request.recv(4).decode()
        #         z12_23 = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
        #         z12_13 = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
        #         self.server.shares_of_arithmetic_z_shares[client_id][0] = (z12_23,z12_13)
            
        #     self.server.is_receive_boolean_share_done = True

        # # Server 2 sends (z23_12,z23_13) to Server 1
        # elif request.decode() == REQUESTS[31]:
        #     self.logger.info('receive request: SERVER-2-BOOLEANSHAR')
        #     for i in range(self.server.num_clients):
        #         client_id = self.request.recv(4).decode()
        #         z23_12 = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
        #         z23_13 = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
        #         self.server.shares_of_arithmetic_z_shares[client_id][2] = (z23_12,z23_13)
            
        #     self.server.is_receive_boolean_share_done = True

        # # Server sends (z13_12,z13_23) to Server 2
        # elif request.decode() == REQUESTS[32]:
        #     self.logger.info('receive request: SERVER-3-BOOLEANSHAR')
        #     for i in range(self.server.num_clients):
        #         client_id = self.request.recv(4).decode()
        #         z13_12 = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
        #         z13_23 = int.from_bytes(self.request.recv(self.server.num_bytes), sys.byteorder)
        #         self.server.shares_of_arithmetic_z_shares[client_id][1] = (z13_12,z13_23)

        #     self.server.is_receive_boolean_share_done = True

        # # Server 1 sends h(z13_12||z13_23) to Server 2
        # elif request.decode() == REQUESTS[33]:
        #     hash = self.request.recv(32)
        #     self.server.received_hash_of_z_shares = hash 
        #     self.server.is_receive_boolean_share_hash_done = True

        # # Server 2 sends h(z12_23||z12_13) to Server 3
        # elif request.decode() == REQUESTS[34]:
        #     hash = self.request.recv(32)
        #     self.server.received_hash_of_z_shares = hash 
        #     self.server.is_receive_boolean_share_hash_done = True

        # # Server 3 sends h(z23_12||z23_13) to Server 1
        # elif request.decode() == REQUESTS[35]:
        #     hash = self.request.recv(32)
        #     self.server.received_hash_of_z_shares = hash 
        #     self.server.is_receive_boolean_share_hash_done = True 

        # Servers send intermediate results for Boolean addition 
        # elif request.decode() == REQUESTS[36] or \
        #      request.decode() == REQUESTS[37] or \
        #      request.decode() == REQUESTS[38]:
        #     for i in range(self.server.num_clients):
        #         client_id = self.request.recv(4).decode()
        #         share = self.request.recv(self.server.ring_size).decode()
        #         if self.id == 1:
        #             self.server.received_one_server_shares_1[client_id][1] = share
        #         else:
        #             self.server.received_one_server_shares_1[client_id][0] = share

        #     self.server.is_receive_one_server_shares_1_done = True

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
            if request.decode() == REQUESTS[33]:
                self.logger.info('receive request: SERVER-1-VIEWDIFFERE')
            elif request.decode() == REQUESTS[34]:
                self.logger.info('receive request: SERVER-2-VIEWDIFFERE')
            else:
                self.logger.info('receive request: SERVER-3-VIEWDIFFERE')
            self.server.received_view_of_differences = self.request.recv(32)
            self.server.is_receive_view_of_differences_done = True
        
        else:
            self.logger.error("unknown request.")

if __name__ == '__main__':
    import sys 
    import getopt 
    try:
        opts, args = getopt.getopt(sys.argv[1:],"i:p:n:",["id=","port=","num_clients="])
    except getopt.GetoptError as e:
        print(e.msg)
        print(e.opt)
        sys.exit(2)

    id, port, num_clients = 0, 0, 0
    for opt, arg in opts:
        if opt in ("-i","--id"):
            id = int(arg)
        elif opt in ("-p","--port"):
            port = int(arg)
        elif opt in ("-n","--num_clients"):
            num_clients = int(arg)
    
    address_server = ('localhost', port) 
    server = ThreadedServer(id=id, num_clients=num_clients, 
                            address=address_server, handler_class=ThreadedRequestHandler)
    server.serve_forever()



