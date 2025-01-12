import os
import math
import random 
import numpy as np
from typing import List, Tuple
from ThreePartySS import ThreePartySS

class Client(object):
    def __init__(self, id : int, data : List[int], SS_type : str = "t1", ring_size : int = 1) -> None:
        self.id = id
        self.data = data
        self.data_dimension = len(data)
        self.ring_size = ring_size
        self.mask = pow(2, ring_size) - 1
        self.SS_obj = ThreePartySS(type = SS_type, ring_size = ring_size)
        self.shares = []
        self.s_0, self.s_1 = 0, 0
        self.shares_of_S1 = []
        self.shares_of_S2 = []
        self.shares_of_S3 = []
        self.shares_of_square_S1 = []
        self.shares_of_square_S2 = []
        self.shares_of_square_S3 = []
        self.shares_sent_to_S1 = []
        self.shares_sent_to_S2 = []
        self.shares_sent_to_S3 = []
        # for i in range(self.data_dimension):
        #     self.shares.append(self.SS_obj.share(self.data[i]))

    # send shares via network communication 
    def send_shares(self) -> bool:
        pass

    # send shares locally, for simulation
    def send_shares_locally(self) -> Tuple[List[List[Tuple[int]]],List[List[Tuple[Tuple[int]]]]]:
        return ([self.shares_of_S1, self.shares_of_S2, self.shares_of_S3],
                [self.shares_of_square_S1, self.shares_of_square_S2, self.shares_of_square_S3])
    
    # send reduced shares to servers locally, for simulation 
    def send_reduced_shares_locally(self) -> Tuple[List]:
        return (self.shares_sent_to_S1, self.shares_sent_to_S2, self.shares_sent_to_S3)

    # share generation
    def generate_shares(self) -> bool: 
        # select three random seeds
        num_bytes = math.ceil(self.ring_size / 8)
        s_0, self.s_0 = [int.from_bytes(os.urandom(num_bytes), 'big')] * 2
        s_1, self.s_1 = [int.from_bytes(os.urandom(num_bytes), 'big')] * 2
        
        self.shares_sent_to_S1.append(s_0)
        self.shares_sent_to_S1.append(s_1)
        self.shares_sent_to_S1.append(self.data_dimension)
        self.shares_sent_to_S2.append(s_0)
        self.shares_sent_to_S3.append(s_1)

        for i in range(self.data_dimension):
            random.seed(s_0)
            s_0 += 1
            x_i_12 = random.randint(0, pow(2, self.ring_size)-1)
            random.seed(s_1)
            s_1 += 1
            x_i_13 = random.randint(0, pow(2, self.ring_size)-1)
            # compute x_i_23
            x_i_23 = self.data[i] ^ x_i_12 ^ x_i_13

            # extract boolean shares 
            shares_of_S1, shares_of_S2, shares_of_S3 = self.extract_boolean_shares((x_i_12,
                                                                                    x_i_13,
                                                                                    x_i_23))
            
            # extract partial boolean shares to send to servers
            partial_shares_of_S2, partial_shares_of_S3 = self.extract_partial_boolean_shares(x_i_23)
            self.shares_sent_to_S2.append(partial_shares_of_S2)
            self.shares_sent_to_S3.append(partial_shares_of_S3)

            # generate random square correlation pairs 
            alpha_i = int.from_bytes(os.urandom(num_bytes), 'big') & self.mask
            beta_i = pow(alpha_i, 2) & self.mask
            # generate shares
            alpha_i_12 = int.from_bytes(os.urandom(num_bytes), 'big') & self.mask
            alpha_i_13 = int.from_bytes(os.urandom(num_bytes), 'big') & self.mask
            alpha_i_23 = (alpha_i - alpha_i_12- alpha_i_13) & self.mask
            beta_i_12 = int.from_bytes(os.urandom(num_bytes), 'big') & self.mask
            beta_i_13 = int.from_bytes(os.urandom(num_bytes), 'big') & self.mask
            beta_i_23 = (beta_i - beta_i_12 - beta_i_13) & self.mask

            self.shares_of_S1.append(shares_of_S1)
            self.shares_of_S2.append(shares_of_S2)
            self.shares_of_S3.append(shares_of_S3)

            self.shares_of_square_S1.append(((alpha_i_12, beta_i_12),(alpha_i_13, beta_i_13)))
            self.shares_of_square_S2.append(((alpha_i_12, beta_i_12),(alpha_i_23, beta_i_23)))
            self.shares_of_square_S3.append(((alpha_i_23, beta_i_23),(alpha_i_13, beta_i_13)))

        return True
    
    # extract boolean shares
    def extract_boolean_shares(self, shares : Tuple[int]) -> List[List[Tuple[int]]]:
        assert len(shares) == 3
        shares_of_S1, shares_of_S2, shares_of_S3 = [], [], []
        x_12 = shares[0]
        x_13 = shares[1]
        x_23 = shares[2]
        for i in range(self.ring_size):
            x_12_i = x_12 & 1
            x_12 >>= 1
            x_13_i = x_13 & 1
            x_13 >>= 1
            x_23_i = x_23 & 1
            x_23 >>= 1
            shares_of_S1.append((x_12_i, x_13_i))
            shares_of_S2.append((x_12_i, x_23_i))
            shares_of_S3.append((x_23_i, x_13_i))
        
        return [shares_of_S1, shares_of_S2, shares_of_S3]

    # extract partial boolean shares
    def extract_partial_boolean_shares(self, x_23 : int) -> Tuple[List[int]]:
        shares_of_S2, shares_of_S3 = [], []
        for i in range(self.ring_size):
            x_23_i = x_23 & 1
            x_23 >>= 1
            shares_of_S2.append(x_23_i)
            shares_of_S3.append(x_23_i)
        
        return (shares_of_S2, shares_of_S3)

    # simulate share conversion, discarded
    # def simulate_share_conversion(self, server_id : int, shares : List[Tuple[int]]) -> Tuple[int]:
    #     assert server_id == 1 or server_id == 2 or server_id == 3
    #     assert len(shares) == self.ring_size
    #     x_12, x_13, x_23 = 0, 0, 0
    #     for i in range(self.ring_size):
    #         if server_id == 1 or server_id == 2:
    #             x_12 += (pow(2, i) * (shares[i][0] + shares[i][1] - 
    #                                   2 * shares[i][0] * shares[i][1])) & self.mask
    #         if server_id == 1 or server_id == 3:                
    #             x_13 += (pow(2, i) * (shares[i][2] - 2 * shares[i][0] *
    #                                   shares[i][2])) & self.mask                
    #         if server_id == 2:
    #             x_23 += (pow(2, i) * (shares[i][2] - 2 * shares[i][0] *
    #                                   shares[i][2])) & self.mask
    #         if server_id == 3:
    #             x_23 += (pow(2, i) * (shares[i][1] - 2 * shares[i][0] *
    #                                   shares[i][1])) & self.mask
    #     if server_id == 1:
    #         return (x_12, x_13)
    #     elif server_id == 2:
    #         return (x_12, x_23)
    #     else:
    #         return (x_23, x_13)
