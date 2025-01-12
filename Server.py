import math
import random 
from Utility import extract_boolean_shares
from typing import List, Tuple, Union
from cryptography.hazmat.primitives import hashes, hmac

class Server(object):
    def __init__(self, id : int = 1, 
                 SS_type : str = "t1", 
                 ring_size : int = 1, 
                 keys : Tuple[int] = (0, 0, 0),
                 PRF_counters : Tuple[int] = (0, 0, 0)) -> None:
        # id=1, share form:((m), share_12, share_13)
        # id=2, share form:((m), share_12, share_23)
        # id=3, share form:((m), share_23, share_13)
        assert id == 1 or id == 2 or id == 3
        self.id = id
        self.current_SS_type = SS_type
        self.ring_size = ring_size
        self.num_bytes = math.ceil(ring_size / 8)
        # operation 'mod 2^l' is equivalent to operation '& (2^l-1)'
        # and the latter is far more efficient
        self.mask = pow(2, ring_size)-1 
        self.shares = {}
        self.data_dimension = 0
        self.active_secrets = [0 for i in range(self.data_dimension)]
        self.active_view = b''
        self.kS = keys[2]
        self.ctrS = PRF_counters[2]
        if id == 1:
            self.key12 = keys[0]
            self.key13 = keys[1]
            self.ctr12 = PRF_counters[0]
            self.ctr13 = PRF_counters[1]
        elif id == 2:
            self.key12 = keys[0]
            self.key23 = keys[1]       
            self.ctr12 = PRF_counters[0]         
            self.ctr23 = PRF_counters[1]
        else:
            self.key13 = keys[0]
            self.key23 = keys[1]
            self.ctr13 = PRF_counters[0]
            self.ctr23 = PRF_counters[1]
        self.zero_share = 0
        self.y_share = 0
        self.y_share_t1 = {}
        self.y_reduced_share_t1 = {}
        # form of the shares of a's of the random square correlation pairs:
        # id=1, [(a1_12,a1_13),(a2_12,a2_13),...]
        # id=2, [(a1_12,a1_23),...]
        # id=3, [(a1_23,a1_13),...]
        self.random_square_correlation_pair_a_shares = []
        # form of the shares of c's of the random square correlation pairs:
        # id=1, [(c1_12,c1_13),(c2_12,c2_13),...]
        # id=2, [(c1_12,c1_23),...]
        # id=3, [(c1_23,c1_13),...]
        self.random_square_correlation_pair_c_shares = []
        self.norm_check_alpha = 0
        # shares of \rho_i,i=1,...,d, the form:
        # id=1, [(rho1_12,rho1_13),(rho2_12,rho2_13)...]
        # id=2, [(rho1_12,rho1_23),...]
        # id=3, [(rho1_23,rho1_13),...]
        self.rho_shares = {}
        # shares of \sigma_i,i=1,...,d, the form:
        # id=1, [(sigma1_12,sigma1_13),(sigma2_12,sigma2_13)...]
        # id=2, [(sigma1_12,sigma1_23),...]
        # id=3, [(sigma1_23,sigma1_13),...]
        self.sigma_shares = {}
        self.rhos_sigmas_opened = {}
        self.v_share_t1 = None
        self.v_opened = 0
        # id=1, [[(x_i_12_12,x_i_12_13),(x_i_13_12,x_i_13_13),(x_i_23_12,x_i_23_13)],...]
        # id=2, [[(x_i_12_12,x_i_12_23),(x_i_23_12,x_i_23_23),(x_i_13_12,x_i_13_23)],...]
        # id=3, [[(x_i_23_23,x_i_23_13),(x_i_13_23,x_i_13_13),(x_i_12_23,x_i_12_13)],...]
        self.shares_of_bit_shares = {}
        # active shares for multiplication
        self.active_shares_of_secrets = {}
        self.shares_of_x12_add_x13 = []
        self.shares_from_share_conversion = {}
        self.shares_of_l2_norm_shares = {}
        self.shares_of_l2_norm_bound = None
        self.shares_of_difference_between_norm_and_bound = {}
        self.difference_between_norm_and_bound = {}
        
    # get boolean shares via network communication
    def get_boolean_shares(self, client_id : str, shares : List[List[Tuple[int]]]) -> bool:
        return True
    
    # get boolean shares locally, for simulation, here ignore the shares of squares
    def get_boolean_shares_locally(self, client_id : str, shares : List[List[Tuple[int]]]) -> bool:
        self.shares[client_id] = shares
        if self.data_dimension == 0:
            self.data_dimension = len(shares)
        else:
            assert len(shares) == self.data_dimension
        return True
    
    # get reduced boolean shares and recover complete shares locally, for simulation, here ignore the shares of squares
    def get_reduced_boolean_shares_locally(self, client_id : str, shares : List) -> bool:
        self.shares[client_id] = []
        if self.id == 1:
            assert len(shares) == 3
            self.data_dimension = shares[2]
            s_0, s_1 = shares[0], shares[1]
            for i in range(self.data_dimension):
                shares_of_dimension_i = []
                random.seed(s_0)
                s_0 += 1
                x_i_12 = random.randint(0, pow(2, self.ring_size)-1)
                random.seed(s_1)
                s_1 += 1
                x_i_13 = random.randint(0, pow(2, self.ring_size)-1)
                # extract boolean shares
                boolean_shares_of_x_i_12 = extract_boolean_shares(value=x_i_12, ring_size=self.ring_size)
                boolean_shares_of_x_i_13 = extract_boolean_shares(value=x_i_13, ring_size=self.ring_size)
                assert len(boolean_shares_of_x_i_12) == self.ring_size and len(boolean_shares_of_x_i_13) == self.ring_size
                for j in range(self.ring_size):
                    shares_of_dimension_i.append((boolean_shares_of_x_i_12[j],boolean_shares_of_x_i_13[j]))
                self.shares[client_id].append(shares_of_dimension_i)
        elif self.id == 2:
            self.data_dimension = len(shares) - 1
            s_0 = shares[0]
            for i in range(self.data_dimension):
                shares_of_dimension_i = []
                random.seed(s_0)
                s_0 += 1
                x_i_12 = random.randint(0, pow(2, self.ring_size)-1)
                # extract boolean shares
                boolean_shares_of_x_i_12 = extract_boolean_shares(value=x_i_12, ring_size=self.ring_size)
                assert len(boolean_shares_of_x_i_12) == self.ring_size
                for j in range(self.ring_size):
                    shares_of_dimension_i.append((boolean_shares_of_x_i_12[j], shares[i+1][j]))
                self.shares[client_id].append(shares_of_dimension_i)
        else:
            self.data_dimension = len(shares) - 1
            s_1 = shares[0]
            for i in range(self.data_dimension):
                shares_of_dimension_i = []
                random.seed(s_1)
                s_1 += 1
                x_i_13 = random.randint(0, pow(2, self.ring_size)-1)
                # extract boolean shares
                boolean_shares_of_x_i_13 = extract_boolean_shares(value=x_i_13, ring_size=self.ring_size)
                assert len(boolean_shares_of_x_i_13) == self.ring_size
                for j in range(self.ring_size):
                    shares_of_dimension_i.append((shares[i+1][j], boolean_shares_of_x_i_13[j]))
                self.shares[client_id].append(shares_of_dimension_i)

        return True
    
    def return_boolean_shares(self, client_id : str, dimension : str) -> List[Tuple[int]]:
        assert client_id in self.shares.keys() and len(self.shares[client_id]) >= int(dimension)
        return self.shares[client_id][int(dimension)-1]

    # get arithmetic shares of a scalar secret for testing
    def get_arithmetic_shares_locally(self, value_id : str, shares : Tuple[int]) -> bool:
        assert len(shares) == 2
        self.active_shares_of_secrets[value_id] = shares

        return True

    # send share via network communication 
    def send_share(self, data_index : int) -> int:
        return 0

    # send share locally, for simulation 
    def send_share_locally(self, data_index : int) -> int:
        assert data_index >= 0 and data_index < self.data_dimension
        if self.current_SS_type == "t1":
            if self.id == 1:    
                return self.shares[data_index][1]
            else:
                return self.shares[data_index][0]
        else:
            if self.id == 1:
                return self.shares[data_index][2]
            else:
                return self.shares[data_index][1]
            
    # send share of 'v' via network communication 
    def send_share_of_v(self) -> int:
        return 0
    
    # send share of 'v' locally, for simulation 
    def send_share_of_v_locally(self) -> int:
        if self.id == 1:
            return self.v_share_t1[1]
        else:
            return self.v_share_t1[0]
        
    # recover 'v' via network communication 
    def recover_v(self, incoming_share : int) -> bool:
        return True

    # recover 'v' locally, for simulation 
    def recover_v_locally(self, incoming_share : int) -> bool:
        v_recovered = (self.v_share_t1[0] + self.v_share_t1[1] + incoming_share) & self.mask
        self.v_opened = v_recovered

        return True

    # send norm check shares required in the open procedure, via network communication 
    def send_rho_sigma_shares(self) -> List[Tuple[int,int]]:
        return [(0,0)]
    
    # send norm check shares required in the open procedure, locally, for simulation  
    def send_rho_sigma_shares_locally(self, client_id : str) -> List[Tuple[int,int]]:
        sent_shares = []
        for i in range(self.data_dimension):
            if self.id == 1:
                sent_shares.append((self.rho_shares[client_id][i][1], self.sigma_shares[client_id][i][1]))
            else:
                sent_shares.append((self.rho_shares[client_id][i][0], self.sigma_shares[client_id][i][0]))
        return sent_shares
    
    # recover rho's and sigma's via network communication 
    def recover_rhos_sigmas(self, incoming_shares : List[Tuple[int,int]]) -> bool:
        return True

    # recover rho's and sigma's locally, for simulation 
    def recover_rhos_sigmas_locally(self, incoming_shares : List[Tuple[int,int]], client_id : str) -> bytes:
        assert len(incoming_shares) == self.data_dimension
        rhos_sigmas_recovered = []
        bytes = b''
        for i in range(self.data_dimension):
            rho_i = (self.rho_shares[client_id][i][0] + self.rho_shares[client_id][i][1] + incoming_shares[i][0]) & self.mask
            bytes += rho_i.to_bytes(self.num_bytes, 'big')
            sigma_i = (self.sigma_shares[client_id][i][0] + self.sigma_shares[client_id][i][1] + incoming_shares[i][1]) & self.mask
            bytes += sigma_i.to_bytes(self.num_bytes, 'big')
            rhos_sigmas_recovered.append((rho_i, sigma_i))
        self.rhos_sigmas_opened[client_id] = rhos_sigmas_recovered
        digest = hashes.Hash(hashes.SHA256())
        digest.update(bytes)
        view = digest.finalize()
        self.active_view = view
        return view

    # get correctness check share which will be sent
    def get_correctness_check_share_being_sent(self, client_id : str) -> List[int]:
        assert client_id in self.shares.keys()
        shares = []
        for i in range(self.data_dimension):
            for j in range(self.ring_size):
                if self.id == 1:
                    shares.append(self.shares[client_id][i][j][0])
                else:
                    shares.append(self.shares[client_id][i][j][1])
        return shares
            
    # get correctness check share which the party holds locally
    def get_correctness_check_share_held(self, client_id : str) -> List[int]:
        assert client_id in self.shares.keys()
        shares = []
        for i in range(self.data_dimension):
            for j in range(self.ring_size):
                if self.id == 1:
                    shares.append(self.shares[client_id][i][j][1])
                else:
                    shares.append(self.shares[client_id][i][j][0])
        return shares

    # send correctness check view via network communication 
    def send_correctness_check_view(self, data_indices : List[int]) -> bool:
        return True
    
    # send correctness check view locally, for simulation 
    def send_correctness_check_view_locally(self, client_ids : Tuple[str]) -> bytes:
        incoming_shares = []
        for i in range(len(client_ids)):
            incoming_shares.append(self.get_correctness_check_share_being_sent(client_ids[i]))

        bytes = b''
        for i in range(len(incoming_shares)):
            for j in range(len(incoming_shares[i])):
                bytes += incoming_shares[i][j].to_bytes(self.num_bytes, 'big')

        digest = hashes.Hash(hashes.SHA256())
        digest.update(bytes)
        result = digest.finalize()

        return result

    # set correctness check view locally
    def set_correctness_check_view(self, client_ids : Tuple[str]) -> bool:
        incoming_shares = []
        for i in range(len(client_ids)):
            incoming_shares.append(self.get_correctness_check_share_held(client_ids[i]))

        bytes = b''
        for i in range(len(incoming_shares)):
            for j in range(len(incoming_shares[i])):
                bytes += incoming_shares[i][j].to_bytes(self.num_bytes, 'big')

        digest = hashes.Hash(hashes.SHA256())
        digest.update(bytes)
        result = digest.finalize()

        self.active_view = result
        return True

    # recover secret via network communication 
    def recover(self, data_index : int, incoming_share : int) -> bool:
        return True

    # recover secret locally, for simulation
    def recover_locally(self, data_index : int, incoming_share : int) -> bool:
        assert data_index >= 0 and data_index < self.data_dimension
        if self.current_SS_type == "t1":
            secret = (self.shares[data_index][0] + self.shares[data_index][1] + incoming_share) & self.mask
        else:
            lambda_value = (self.shares[data_index][1] + self.shares[data_index][2] + incoming_share) & self.mask
            secret = (self.shares[data_index][0] - lambda_value) & self.mask

        self.active_secrets[data_index] = secret
        return True
    
    # send view via network communication 
    def send_view(self, data_indices : List[int]) -> bytes:
        return b'0'
    
    # send view locally, for simulation
    def send_view_locally(self, data_indices : List[int]) -> bytes:
        bytes = b''
        for i in range(len(data_indices)):
            assert data_indices[i] >= 0 and data_indices[i] < self.data_dimension
            bytes += self.active_secrets[data_indices[i]].to_bytes(self.num_bytes, 'big')

        digest = hashes.Hash(hashes.SHA256())
        digest.update(bytes)
        result = digest.finalize()

        self.active_view = result
        return result

    # send view of opened 'v' via network communication 
    def send_view_of_v(self) -> bytes:
        return b''
    
    # send view of opened 'v' locally, for simulation 
    def send_view_of_v_locally(self) -> bytes:
        bytes = self.v_opened.to_bytes(self.num_bytes, 'big')
        digest = hashes.Hash(hashes.SHA256())
        digest.update(bytes)
        result = digest.finalize()

        self.active_view = result
        return result        

    # compare view via network communication 
    def compare_view(self, incoming_hash : bytes) -> bool:
        return True

    # compare view locally, for simulation
    def compare_view_locally(self, incoming_hash : bytes) -> bool:
        if self.active_view == incoming_hash:
            return True
        else:
            return False

    # compare view via network communication 
    def compare_view(self, incoming_hash : bytes) -> bool:
        return True
    
    # compare view locally, for simulation 
    def compare_view_locally(self, incoming_hash : bytes) -> bool:
        if self.active_view == incoming_hash:
            return True
        else:
            return False

    # generate zero share on demand
    def generate_zero_share(self) -> int:
        if self.id == 1:
            key12_bytes = self.key12.to_bytes(self.num_bytes, 'big')
            key13_bytes = self.key13.to_bytes(self.num_bytes, 'big')
            ctr12_bytes = self.ctr12.to_bytes(self.num_bytes, 'big')
            ctr13_bytes = self.ctr13.to_bytes(self.num_bytes, 'big')
            hmac_obj = hmac.HMAC(key12_bytes, hashes.SHA256())
            hmac_obj.update(ctr12_bytes)
            Fk12_ctr12 = int.from_bytes(hmac_obj.finalize(), "big") & self.mask
            hmac_obj = hmac.HMAC(key13_bytes, hashes.SHA256())
            hmac_obj.update(ctr13_bytes)
            Fk13_ctr13 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
            # compute alpha
            self.zero_share = (Fk12_ctr12 - Fk13_ctr13) & self.mask
            # update PRF counter 
            self.ctr12 += 1
            self.ctr13 += 1
        elif self.id == 2:
            key23_bytes = self.key23.to_bytes(self.num_bytes, 'big')
            key12_bytes = self.key12.to_bytes(self.num_bytes, 'big')
            ctr23_bytes = self.ctr23.to_bytes(self.num_bytes, 'big')
            ctr12_bytes = self.ctr12.to_bytes(self.num_bytes, 'big')
            hmac_obj = hmac.HMAC(key23_bytes, hashes.SHA256())
            hmac_obj.update(ctr23_bytes)
            Fk23_ctr23 = int.from_bytes(hmac_obj.finalize(), "big") & self.mask
            hmac_obj = hmac.HMAC(key12_bytes, hashes.SHA256())
            hmac_obj.update(ctr12_bytes)
            Fk12_ctr12 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
            # compute beta
            self.zero_share = (Fk23_ctr23 - Fk12_ctr12) & self.mask
            # update PRF counter
            self.ctr23 += 1
            self.ctr12 += 1
        else:
            key13_bytes = self.key13.to_bytes(self.num_bytes, 'big')
            key23_bytes = self.key23.to_bytes(self.num_bytes, 'big')
            ctr13_bytes = self.ctr13.to_bytes(self.num_bytes, 'big')
            ctr23_bytes = self.ctr23.to_bytes(self.num_bytes, 'big')
            hmac_obj = hmac.HMAC(key13_bytes, hashes.SHA256())
            hmac_obj.update(ctr13_bytes)
            Fk13_ctr13 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
            hmac_obj = hmac.HMAC(key23_bytes, hashes.SHA256())
            hmac_obj.update(ctr23_bytes)
            Fk23_ctr23 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
            # compute gamma
            self.zero_share = (Fk13_ctr13 - Fk23_ctr23) & self.mask
            # update PRF counter 
            self.ctr13 += 1
            self.ctr23 += 1
        return self.zero_share

    # generate (3,3)-sharing of y, which is the squared l2-norm of secret vectors
    def generate_33share_of_y(self, client_id : str) -> int:
        assert client_id in self.shares_from_share_conversion.keys()
        share_of_y = self.zero_share
        if self.id == 1:
            squared_xi_12 = 0
            twice_xi_12_xi_13 = 0
            for i in range(self.data_dimension):
                assert str(i+1) in self.shares_from_share_conversion[client_id].keys()
                squared_xi_12 = (squared_xi_12 + pow(self.shares_from_share_conversion[client_id][str(i+1)][0], 2)) & self.mask
                twice_xi_12_xi_13 = (twice_xi_12_xi_13 + 2 * self.shares_from_share_conversion[client_id][str(i+1)][0] * 
                                      self.shares_from_share_conversion[client_id][str(i+1)][1]) & self.mask
            share_of_y = (share_of_y + squared_xi_12 + twice_xi_12_xi_13) & self.mask
        elif self.id == 2:
            squared_xi_23 = 0
            twice_xi_12_xi_23 = 0
            for i in range(self.data_dimension):
                squared_xi_23 = (squared_xi_23 + pow(self.shares_from_share_conversion[client_id][str(i+1)][1], 2)) & self.mask
                twice_xi_12_xi_23 = (twice_xi_12_xi_23 + 2 * self.shares_from_share_conversion[client_id][str(i+1)][0] * 
                                      self.shares_from_share_conversion[client_id][str(i+1)][1]) & self.mask
            share_of_y = (share_of_y + squared_xi_23 + twice_xi_12_xi_23) & self.mask

        else:
            squared_xi_13 = 0
            twice_xi_13_xi_23 = 0
            for i in range(self.data_dimension):
                squared_xi_13 = (squared_xi_13 + pow(self.shares_from_share_conversion[client_id][str(i+1)][1], 2)) & self.mask
                twice_xi_13_xi_23 = (twice_xi_13_xi_23 + 2 * self.shares_from_share_conversion[client_id][str(i+1)][0] * 
                                      self.shares_from_share_conversion[client_id][str(i+1)][1]) & self.mask
            share_of_y = (share_of_y + squared_xi_13 + twice_xi_13_xi_23) & self.mask

        self.y_share = share_of_y
        return share_of_y
    
    # generate (3,3)-sharing of output of semi-honest multiplication subprotocol
    def generate_33share_of_output(self, operands_id : List[str]) -> int:
        assert len(operands_id) == 2
        share_of_output = self.zero_share
        if self.id == 1:
            share_of_output = (share_of_output + 
                               self.active_shares_of_secrets[operands_id[0]][0] * self.active_shares_of_secrets[operands_id[1]][0] +
                               self.active_shares_of_secrets[operands_id[0]][0] * self.active_shares_of_secrets[operands_id[1]][1] +
                               self.active_shares_of_secrets[operands_id[0]][1] * self.active_shares_of_secrets[operands_id[1]][0]) & self.mask
        else:
            share_of_output = (share_of_output + 
                               self.active_shares_of_secrets[operands_id[0]][1] * self.active_shares_of_secrets[operands_id[1]][1] +
                               self.active_shares_of_secrets[operands_id[0]][0] * self.active_shares_of_secrets[operands_id[1]][1] +
                               self.active_shares_of_secrets[operands_id[0]][1] * self.active_shares_of_secrets[operands_id[1]][0]) & self.mask
            
        self.y_share = share_of_output
        return share_of_output

    # set t1-sharing of y, with a share received from another server, via network communication 
    def set_t1_sharing_of_y(self, share_received : int) -> bool:
        return True
    
    # set t1-sharing of y, with a share received from another server, locally, for simulation 
    def set_t1_sharing_of_y_locally(self, share_received : int, client_id : str = 'multiplication') -> Tuple[int]:
        if self.id == 1:
            self.y_share_t1[client_id] = (self.y_share, share_received)
        else:
            self.y_share_t1[client_id] = (share_received, self.y_share)
        
        return self.y_share_t1[client_id]
    
    # set reduced sharing of y
    def set_reduced_t1_sharing_of_y_locally(self, shares : Tuple[int], client_id : str) -> bool:
        self.y_reduced_share_t1[client_id] = shares
        return True
    
    # generate a random common non-zero value alpha
    def generate_nonzero_alpha(self) -> bool:
        kS_bytes = self.kS.to_bytes(self.num_bytes, 'big')
        ctrS_bytes = self.ctrS.to_bytes(self.num_bytes, 'big')
        hmac_obj = hmac.HMAC(kS_bytes, hashes.SHA256())
        hmac_obj.update(ctrS_bytes)
        FkS_ctrS = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
        while(FkS_ctrS == 0):
            # update PRF counter
            self.ctrS += 1
            ctrS_bytes = self.ctrS.to_bytes(self.num_bytes, 'big')
            hmac_obj = hmac.HMAC(kS_bytes, hashes.SHA256())
            hmac_obj.update(ctrS_bytes)
            FkS_ctrS = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
        self.norm_check_alpha = FkS_ctrS
        # update PRF counter 
        self.ctrS += 1

    # compute [\rho_i],[\sigma_i],i=1,...,d
    def compute_rho_sigma_shares(self, client_id : str)-> bool:
        if client_id in self.rho_shares.keys():
            pass
        else:
            self.rho_shares[client_id] = []
        if client_id in self.sigma_shares.keys():
            pass
        else:
            self.sigma_shares[client_id] = []
        
        if self.id == 1:
            for i in range(self.data_dimension):
                # compute [\rho_i]=\alpha[x_i]+[a_i]
                rhoi_12 = (self.norm_check_alpha * self.shares_from_share_conversion[client_id][str(i+1)][0] + self.random_square_correlation_pair_a_shares[i][0]) & self.mask
                rhoi_13 = (self.norm_check_alpha * self.shares_from_share_conversion[client_id][str(i+1)][1] + self.random_square_correlation_pair_a_shares[i][1]) & self.mask
                self.rho_shares[client_id].append((rhoi_12,rhoi_13))
                # compute [\sigma_i]=[x_i]+[a_i]
                sigmai_12 = (self.shares_from_share_conversion[client_id][str(i+1)][0] + self.random_square_correlation_pair_a_shares[i][0]) & self.mask
                sigmai_13 = (self.shares_from_share_conversion[client_id][str(i+1)][1] + self.random_square_correlation_pair_a_shares[i][1]) & self.mask
                self.sigma_shares[client_id].append((sigmai_12, sigmai_13))
        elif self.id == 2:
            for i in range(self.data_dimension):
                rhoi_12 = (self.norm_check_alpha * self.shares_from_share_conversion[client_id][str(i+1)][0] + self.random_square_correlation_pair_a_shares[i][0]) & self.mask
                rhoi_23 = (self.norm_check_alpha * self.shares_from_share_conversion[client_id][str(i+1)][1] + self.random_square_correlation_pair_a_shares[i][1]) & self.mask
                self.rho_shares[client_id].append((rhoi_12,rhoi_23))
                sigmai_12 = (self.shares_from_share_conversion[client_id][str(i+1)][0] + self.random_square_correlation_pair_a_shares[i][0]) & self.mask
                sigmai_23 = (self.shares_from_share_conversion[client_id][str(i+1)][1] + self.random_square_correlation_pair_a_shares[i][1]) & self.mask
                self.sigma_shares[client_id].append((sigmai_12, sigmai_23))
        else:
            for i in range(self.data_dimension):
                rhoi_23 = (self.norm_check_alpha * self.shares_from_share_conversion[client_id][str(i+1)][0] + self.random_square_correlation_pair_a_shares[i][0]) & self.mask
                rhoi_13 = (self.norm_check_alpha * self.shares_from_share_conversion[client_id][str(i+1)][1] + self.random_square_correlation_pair_a_shares[i][1]) & self.mask
                self.rho_shares[client_id].append((rhoi_23,rhoi_13))
                sigmai_23 = (self.shares_from_share_conversion[client_id][str(i+1)][0] + self.random_square_correlation_pair_a_shares[i][0]) & self.mask
                sigmai_13 = (self.shares_from_share_conversion[client_id][str(i+1)][1] + self.random_square_correlation_pair_a_shares[i][1]) & self.mask
                self.sigma_shares[client_id].append((sigmai_23, sigmai_13))

        return True
        
        '''
        actually, we can ignore the id to unify the computation as follows:
        for i in range(self.data_dimension):
            rhoi_1 = (self.norm_check_alpha * self.shares[i][0] + self.random_square_correlation_pair_a_shares[i][0]) & self.mask
            rhoi_2 = (self.norm_check_alpha * self.shares[i][1] + self.random_square_correlation_pair_a_shares[i][1]) & self.mask
            self.rho_shares.append((rhoi_1,rhoi_2))
                
            sigmai_1 = (self.shares[i][0] + self.random_square_correlation_pair_a_shares[i][0]) & self.mask
            sigmai_2 = (self.shares[i][1] + self.random_square_correlation_pair_a_shares[i][1]) & self.mask
            self.sigma_shares.append((sigmai_1, sigmai_2))

        However, by identifying the id, we can explicitly write the share labels to make the logic more clear.
        '''

    # compute [v]
    def compute_v_share(self, client_id : str) -> bool:
        v_1 = (self.norm_check_alpha * self.y_share_t1[client_id][0]) & self.mask
        v_2 = (self.norm_check_alpha * self.y_share_t1[client_id][1]) & self.mask
        intermediate_value_1 = 0
        intermediate_value_2 = 0
        for i in range(self.data_dimension):
            if self.id == 1:
                intermediate_value_1 = (intermediate_value_1 + self.rhos_sigmas_opened[client_id][i][1] * self.random_square_correlation_pair_a_shares[i][0] + \
                                     self.rhos_sigmas_opened[client_id][i][0] * self.random_square_correlation_pair_a_shares[i][0] - \
                                     self.rhos_sigmas_opened[client_id][i][0] * self.rhos_sigmas_opened[client_id][i][1] - \
                                     self.random_square_correlation_pair_c_shares[i][0]) & self.mask
                intermediate_value_2 = (intermediate_value_2 + self.rhos_sigmas_opened[client_id][i][1] * self.random_square_correlation_pair_a_shares[i][1] + \
                                     self.rhos_sigmas_opened[client_id][i][0] * self.random_square_correlation_pair_a_shares[i][1] - \
                                     self.random_square_correlation_pair_c_shares[i][1]) & self.mask
            elif self.id == 2:
                intermediate_value_1 = (intermediate_value_1 + self.rhos_sigmas_opened[client_id][i][1] * self.random_square_correlation_pair_a_shares[i][0] + \
                                     self.rhos_sigmas_opened[client_id][i][0] * self.random_square_correlation_pair_a_shares[i][0] - \
                                     self.rhos_sigmas_opened[client_id][i][0] * self.rhos_sigmas_opened[client_id][i][1] - \
                                     self.random_square_correlation_pair_c_shares[i][0]) & self.mask
                intermediate_value_2 = (intermediate_value_2 + self.rhos_sigmas_opened[client_id][i][1] * self.random_square_correlation_pair_a_shares[i][1] + \
                                     self.rhos_sigmas_opened[client_id][i][0] * self.random_square_correlation_pair_a_shares[i][1] - \
                                     self.random_square_correlation_pair_c_shares[i][1]) & self.mask
            else:
                intermediate_value_1 = (intermediate_value_1 + self.rhos_sigmas_opened[client_id][i][1] * self.random_square_correlation_pair_a_shares[i][0] + \
                                     self.rhos_sigmas_opened[client_id][i][0] * self.random_square_correlation_pair_a_shares[i][0] - \
                                     self.random_square_correlation_pair_c_shares[i][0]) & self.mask
                intermediate_value_2 = (intermediate_value_2 + self.rhos_sigmas_opened[client_id][i][1] * self.random_square_correlation_pair_a_shares[i][1] + \
                                     self.rhos_sigmas_opened[client_id][i][0] * self.random_square_correlation_pair_a_shares[i][1] - \
                                     self.random_square_correlation_pair_c_shares[i][1]) & self.mask
        v_1 = (v_1 + intermediate_value_1) & self.mask
        v_2 = (v_2 + intermediate_value_2) & self.mask
        if self.id == 1:
            v_12 = v_1
            v_13 = v_2
            self.v_share_t1 = (v_12, v_13)
        elif self.id == 2:
            v_12 = v_1
            v_23 = v_2
            self.v_share_t1 = (v_12, v_23)
        else:
            v_23 = v_1
            v_13 = v_2
            self.v_share_t1 = (v_23, v_13)
        
        return True

    # check if the opened 'v' is 0
    def check_v(self) -> bool:
        return True if self.v_opened == 0 else False
    
    # set sharings of random squared correlation pairs
    def set_shares_of_random_squared_correlation_pairs(self, label : str, shares : Tuple[int]) -> bool:
        assert (label == 'a' or label == 'c') and len(shares) == 2
        if label == 'a':
            self.random_square_correlation_pair_a_shares.append(shares)
        else:
            self.random_square_correlation_pair_c_shares.append(shares)

        return True
    
    # share conversion, from 
    # '[(m,lambda_12,lambda_13),(m,lambda_12,lambda_23),(m,lambda_23,lambda_13)]' to 
    # '[(x_12,x_13),(x_12,x_23),(x_23,x_13)]'
    # def convert_share(self, shares_with_type_B2 : List[Tuple[int]]) -> Tuple[int]:
    #     assert len(shares_with_type_B2) == self.ring_size
    #     x_12, x_13, x_23 = 0, 0, 0
    #     for i in range(self.ring_size):
    #         if self.id == 1 or self.id == 2:
    #             x_12 += (pow(2, i) * (shares_with_type_B2[i][0] + shares_with_type_B2[i][1] - 
    #                                   2 * shares_with_type_B2[i][0] * shares_with_type_B2[i][1])) & self.mask
    #         if self.id == 1 or self.id == 3:                
    #             x_13 += (pow(2, i) * (shares_with_type_B2[i][2] - 2 * shares_with_type_B2[i][0] *
    #                                   shares_with_type_B2[i][2])) & self.mask                
    #         if self.id == 2:
    #             x_23 += (pow(2, i) * (shares_with_type_B2[i][2] - 2 * shares_with_type_B2[i][0] *
    #                                   shares_with_type_B2[i][2])) & self.mask
    #         if self.id == 3:
    #             x_23 += (pow(2, i) * (shares_with_type_B2[i][1] - 2 * shares_with_type_B2[i][0] *
    #                                   shares_with_type_B2[i][1])) & self.mask
    #     if self.id == 1:
    #         return (x_12, x_13)
    #     elif self.id == 2:
    #         return (x_12, x_23)
    #     else:
    #         return (x_23, x_13)

    '''
    param: id=1, boolean_shares = [([x_1]_12,[x_1]_13),([x_2]_12,[x_2]_13),...]
    id=2, boolean_shares = [([x_1]_12,[x_1]_23),([x_2]_12,[x_2]_23),...]
    id=3, boolean_shares = [([x_1]_23,[x_1]_13),([x_2]_23,[x_2]_13),...]
    '''
    def generate_random_shares_of_bits(self, client_id : str, dimension : str) -> List[List[Tuple[int]]]:
        self.shares_of_bit_shares[client_id] = {}
        self.shares_of_bit_shares[client_id][dimension ] = [[] for i in range(self.ring_size)]
        boolean_shares = self.return_boolean_shares(client_id=client_id, dimension=dimension)
        assert len(boolean_shares) == self.ring_size
        if self.id == 1 or self.id == 2:
            key12_bytes = self.key12.to_bytes(self.num_bytes, 'big')
        if self.id == 1 or self.id == 3:
            key13_bytes = self.key13.to_bytes(self.num_bytes, 'big')
        if self.id == 2 or self.id == 3:
            key23_bytes = self.key23.to_bytes(self.num_bytes, 'big')
        # for i=0,...,\ell-1, generate random []^A shares
        return_shares_S1 = {'to_S2':[], 'to_S3':[]}
        return_shares_S2 = {'to_S1':[], 'to_S3':[]}
        return_shares_S3 = {'to_S1':[], 'to_S2':[]}
        for i in range(len(boolean_shares)):
            if self.id == 1:
                # generate random shares of '[x_i]_12,[x_i]_13,i=0,...,\ell-1'
                ctr12_bytes = self.ctr12.to_bytes(self.num_bytes, 'big')
                ctr13_bytes = self.ctr13.to_bytes(self.num_bytes, 'big')
                # generate random shares of '[x_i]_12'
                hmac_obj = hmac.HMAC(key12_bytes, hashes.SHA256())
                hmac_obj.update(ctr12_bytes)
                x_i_12_12 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                self.ctr12 += 1

                ctr12_bytes = self.ctr12.to_bytes(self.num_bytes, 'big')
                hmac_obj = hmac.HMAC(key12_bytes, hashes.SHA256())
                hmac_obj.update(ctr12_bytes)
                x_i_12_13 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                self.ctr12 += 1

                x_i_12_23 = (boolean_shares[i][0] - x_i_12_12 - x_i_12_13) & self.mask
                x_i_12_shares = (x_i_12_12, x_i_12_13)
                self.shares_of_bit_shares[client_id][dimension ][i].append(x_i_12_shares)

                shares_return_to_S3 = (x_i_12_23, x_i_12_13)
                # generate random shares of '[x_i]_13'
                hmac_obj = hmac.HMAC(key13_bytes, hashes.SHA256())
                hmac_obj.update(ctr13_bytes)
                x_i_13_12 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                self.ctr13 += 1

                ctr13_bytes = self.ctr13.to_bytes(self.num_bytes, 'big')
                hmac_obj = hmac.HMAC(key13_bytes, hashes.SHA256())
                hmac_obj.update(ctr13_bytes)
                x_i_13_13 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                self.ctr13 += 1

                x_i_13_23 = (boolean_shares[i][1] - x_i_13_12 - x_i_13_13) & self.mask
                x_i_13_shares = (x_i_13_12, x_i_13_13)
                self.shares_of_bit_shares[client_id][dimension ][i].append(x_i_13_shares)

                shares_return_to_S2 = (x_i_13_12, x_i_13_23)
                return_shares_S1['to_S2'].append(shares_return_to_S2)
                return_shares_S1['to_S3'].append(shares_return_to_S3)

            elif self.id == 2:
                # generate random shares of '[x_i]_12,[x_i]_23,i=0,...,\ell-1'
                ctr12_bytes = self.ctr12.to_bytes(self.num_bytes, 'big')
                ctr23_bytes = self.ctr23.to_bytes(self.num_bytes, 'big')
                # generate random shares of '[x_i]_12'
                hmac_obj = hmac.HMAC(key12_bytes, hashes.SHA256())
                hmac_obj.update(ctr12_bytes)
                x_i_12_12 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                self.ctr12 += 1

                ctr12_bytes = self.ctr12.to_bytes(self.num_bytes, 'big')
                hmac_obj = hmac.HMAC(key12_bytes, hashes.SHA256())
                hmac_obj.update(ctr12_bytes)
                x_i_12_13 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                self.ctr12 += 1

                x_i_12_23 = (boolean_shares[i][0] - x_i_12_12 - x_i_12_13) & self.mask
                x_i_12_shares = (x_i_12_12, x_i_12_23)
                self.shares_of_bit_shares[client_id][dimension ][i].append(x_i_12_shares)

                shares_return_to_S3 = (x_i_12_23, x_i_12_13)

                # generate random shares of '[x_i]_23'
                hmac_obj = hmac.HMAC(key23_bytes, hashes.SHA256())
                hmac_obj.update(ctr23_bytes)
                x_i_23_12 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                self.ctr23 += 1

                ctr23_bytes = self.ctr23.to_bytes(self.num_bytes, 'big')
                hmac_obj = hmac.HMAC(key23_bytes, hashes.SHA256())
                hmac_obj.update(ctr23_bytes)
                x_i_23_13 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                self.ctr23 += 1

                x_i_23_23 = (boolean_shares[i][1] - x_i_23_12 - x_i_23_13) & self.mask
                x_i_23_shares = (x_i_23_12, x_i_23_23)
                self.shares_of_bit_shares[client_id][dimension ][i].append(x_i_23_shares)

                shares_return_to_S1 = (x_i_23_12, x_i_23_13)
                return_shares_S2['to_S1'].append(shares_return_to_S1)
                return_shares_S2['to_S3'].append(shares_return_to_S3)

            else:
                # generate random shares of '[x_i]_23,[x_i]_13,i=0,...,\ell-1'
                ctr13_bytes = self.ctr13.to_bytes(self.num_bytes, 'big')
                ctr23_bytes = self.ctr23.to_bytes(self.num_bytes, 'big')
                # generate random shares of '[x_i]_23'
                hmac_obj = hmac.HMAC(key23_bytes, hashes.SHA256())
                hmac_obj.update(ctr23_bytes)
                x_i_23_12 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                self.ctr23 += 1

                ctr23_bytes = self.ctr23.to_bytes(self.num_bytes, 'big')
                hmac_obj = hmac.HMAC(key23_bytes, hashes.SHA256())
                hmac_obj.update(ctr23_bytes)
                x_i_23_13 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                self.ctr23 += 1

                x_i_23_23 = (boolean_shares[i][0] - x_i_23_12 - x_i_23_13) & self.mask
                x_i_23_shares = (x_i_23_23, x_i_23_13)
                self.shares_of_bit_shares[client_id][dimension ][i].append(x_i_23_shares)

                shares_return_to_S1 = (x_i_23_12, x_i_23_13)

                # generate random shares of '[x_i]_{13}'
                hmac_obj = hmac.HMAC(key13_bytes, hashes.SHA256())
                hmac_obj.update(ctr13_bytes)
                x_i_13_12 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                self.ctr13 += 1

                ctr13_bytes = self.ctr13.to_bytes(self.num_bytes, 'big')
                hmac_obj = hmac.HMAC(key13_bytes, hashes.SHA256())
                hmac_obj.update(ctr13_bytes)
                x_i_13_13 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                self.ctr13 += 1

                x_i_13_23 = (boolean_shares[i][1] - x_i_13_12 - x_i_13_13) & self.mask
                x_i_13_shares = (x_i_13_23, x_i_13_13)
                self.shares_of_bit_shares[client_id][dimension ][i].append(x_i_13_shares)

                shares_return_to_S2 = (x_i_13_12, x_i_13_23)
                return_shares_S3['to_S1'].append(shares_return_to_S1)
                return_shares_S3['to_S2'].append(shares_return_to_S2)

        if self.id == 1:
            return return_shares_S1
        elif self.id == 2:
            return return_shares_S2
        else:
            return return_shares_S3
    
    # compute arithmetic shares of [x_i]_12+[x_i]_{13} for i=0,...,\ell-1
    def compute_arithmetic_shares_of_x12_add_x13(self, client_id : str, dimension : str) -> List[Tuple[int]]:
        shares_of_x12_add_x13 = []
        for i in range(self.ring_size):
            if self.id == 1:
                xi_12_12_add_xi_13_12 = (self.shares_of_bit_shares[client_id][dimension ][i][0][0] + 
                                         self.shares_of_bit_shares[client_id][dimension ][i][1][0]) & self.mask
                xi_12_13_add_xi_13_13 = (self.shares_of_bit_shares[client_id][dimension ][i][0][1] + 
                                         self.shares_of_bit_shares[client_id][dimension ][i][1][1]) & self.mask
                shares_of_x12_add_x13.append((xi_12_12_add_xi_13_12, xi_12_13_add_xi_13_13))
                self.active_shares_of_secrets['x'+str(i)+'12'] = self.shares_of_bit_shares[client_id][dimension ][i][0]
                self.active_shares_of_secrets['x'+str(i)+'13'] = self.shares_of_bit_shares[client_id][dimension ][i][1]
                
            elif self.id == 2:
                xi_12_12_add_xi_13_12 = (self.shares_of_bit_shares[client_id][dimension ][i][0][0] + 
                                         self.shares_of_bit_shares[client_id][dimension ][i][2][0]) & self.mask
                xi_12_23_add_xi_13_23 = (self.shares_of_bit_shares[client_id][dimension ][i][0][1] + 
                                         self.shares_of_bit_shares[client_id][dimension ][i][2][1]) & self.mask
                shares_of_x12_add_x13.append((xi_12_12_add_xi_13_12, xi_12_23_add_xi_13_23))
                self.active_shares_of_secrets['x'+str(i)+'12'] = self.shares_of_bit_shares[client_id][dimension ][i][0]
                self.active_shares_of_secrets['x'+str(i)+'13'] = self.shares_of_bit_shares[client_id][dimension ][i][2]

            else:
                xi_12_23_add_xi_13_23 = (self.shares_of_bit_shares[client_id][dimension ][i][2][0] + 
                                         self.shares_of_bit_shares[client_id][dimension ][i][1][0]) & self.mask
                xi_12_13_add_xi_13_13 = (self.shares_of_bit_shares[client_id][dimension ][i][2][1] + 
                                         self.shares_of_bit_shares[client_id][dimension ][i][1][1]) & self.mask
                shares_of_x12_add_x13.append((xi_12_23_add_xi_13_23, xi_12_13_add_xi_13_13))
                self.active_shares_of_secrets['x'+str(i)+'12'] = self.shares_of_bit_shares[client_id][dimension ][i][2]
                self.active_shares_of_secrets['x'+str(i)+'13'] = self.shares_of_bit_shares[client_id][dimension ][i][1]

        return shares_of_x12_add_x13

    # receive shares for share conversion via network communication 
    def receive_shares_for_share_conversion(self, from_server_id : int, shares : List[Tuple[int]]) -> bool:
        return True
    
    # receive shares for share conversion locally, for simulation 
    def receive_shares_for_share_conversion_locally(self, from_server_id : int, 
                                                    shares : List[Tuple[int]], 
                                                    client_id : str, 
                                                    dimension : str) -> bool:
        assert len(shares) == self.ring_size
        if self.id == 1:
            assert from_server_id == 2 or from_server_id == 3
        elif self.id == 2:
            assert from_server_id == 1 or from_server_id == 3
        else:
            assert from_server_id == 1 or from_server_id == 2
        for i in range(self.ring_size):
            if len(self.shares_of_bit_shares[client_id][dimension ][i]) == 2:
                self.shares_of_bit_shares[client_id][dimension ][i].append(shares[i])
            else:
                assert self.shares_of_bit_shares[client_id][dimension ][i][2] == shares[i]

        return True
    
    # set shares of intermediate values '\sigma_i,i=0,...,\ell-1' in share conversion, for simulation 
    def get_shares_of_sigmai_in_share_conversion(self, shares : List[Tuple[int]]) -> bool:
        assert len(shares) == self.ring_size
        self.active_shares_of_secrets['sigmais'] = shares
        for i in range(self.ring_size):
            self.active_shares_of_secrets['sigma'+str(i)] = shares[i]
        return True

    # set shares of intermediate values x_i,i=0,...,\ell-1, in share conversion, for simulation 
    def get_shares_of_xi_in_share_conversion(self, shares : List[Tuple[int]]) -> bool:
        assert len(shares) == self.ring_size
        self.active_shares_of_secrets['xis'] = shares
        return True

    # compute arithmetic shares of \sigma_i + [x_i]_{23} for i=0,...,\ell-1
    def compute_arithmetic_shares_of_sigmai_add_x23(self, client_id : str, dimension : str) -> List[Tuple[int]]:
        shares_of_sigma_add_x23 = []
        for i in range(self.ring_size):
            if self.id == 1:
                sigmai_12_add_xi_23_12 = (self.active_shares_of_secrets['sigmais'][i][0] + self.shares_of_bit_shares[client_id][dimension ][i][2][0]) & self.mask
                sigmai_13_add_xi_23_13 = (self.active_shares_of_secrets['sigmais'][i][1] + self.shares_of_bit_shares[client_id][dimension ][i][2][1]) & self.mask
                shares_of_sigma_add_x23.append((sigmai_12_add_xi_23_12, sigmai_13_add_xi_23_13))
                self.active_shares_of_secrets['x'+str(i)+'23'] = self.shares_of_bit_shares[client_id][dimension ][i][2]

            elif self.id == 2:
                sigmai_12_add_xi_23_12 = (self.active_shares_of_secrets['sigmais'][i][0] + self.shares_of_bit_shares[client_id][dimension ][i][1][0]) & self.mask
                sigmai_23_add_xi_23_23 = (self.active_shares_of_secrets['sigmais'][i][1] + self.shares_of_bit_shares[client_id][dimension ][i][1][1]) & self.mask
                shares_of_sigma_add_x23.append((sigmai_12_add_xi_23_12, sigmai_23_add_xi_23_23))
                self.active_shares_of_secrets['x'+str(i)+'23'] = self.shares_of_bit_shares[client_id][dimension ][i][1]

            else:
                sigmai_23_add_xi_23_23 = (self.active_shares_of_secrets['sigmais'][i][0] + self.shares_of_bit_shares[client_id][dimension ][i][0][0]) & self.mask
                sigmai_13_add_xi_23_13 = (self.active_shares_of_secrets['sigmais'][i][1] + self.shares_of_bit_shares[client_id][dimension ][i][0][1]) & self.mask
                shares_of_sigma_add_x23.append((sigmai_23_add_xi_23_23, sigmai_13_add_xi_23_13))
                self.active_shares_of_secrets['x'+str(i)+'23'] = self.shares_of_bit_shares[client_id][dimension ][i][0]

        return shares_of_sigma_add_x23
    
    # compute targeted arithmetic shares of secret 
    def generate_targeted_arithmetic_shares(self, client_id : str, dimension : str) -> Tuple[int]:
        if client_id in self.shares_from_share_conversion.keys():
            pass
        else:
            self.shares_from_share_conversion[client_id] = {}
        x_1 = 0
        x_2 = 0
        for i in range(self.ring_size):
            x_1 = (x_1 + pow(2, i) * self.active_shares_of_secrets['xis'][i][0]) & self.mask
            x_2 = (x_2 + pow(2, i) * self.active_shares_of_secrets['xis'][i][1]) & self.mask
        self.shares_from_share_conversion[client_id][dimension] = (x_1, x_2)

        return (x_1, x_2)

    # generate boolean shares with another server
    def generate_boolean_shares_with_another_server(self, server_id : str, client_id : str) -> Union[Tuple[int],bytes]:
        assert client_id in self.y_share_t1.keys()
        if client_id in self.shares_of_l2_norm_shares.keys():
            pass
        else:
            self.shares_of_l2_norm_shares[client_id] = [None,None,None]
        if self.id == 1:
            assert server_id == '2' or server_id == '3'
            if server_id == '2': # generate boolean shares of x_12
                x_12 = self.y_share_t1[client_id][0]
                # generate x_12_12
                key12_bytes = self.key12.to_bytes(self.num_bytes, 'big')
                ctr12_bytes = self.ctr12.to_bytes(self.num_bytes, 'big')
                hmac_obj = hmac.HMAC(key12_bytes, hashes.SHA256())
                hmac_obj.update(ctr12_bytes)
                x_12_12 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                # update ctr
                self.ctr12 += 1
                # generate x_12_13
                ctr12_bytes = self.ctr12.to_bytes(self.num_bytes, 'big')
                hmac_obj = hmac.HMAC(key12_bytes, hashes.SHA256())
                hmac_obj.update(ctr12_bytes)
                x_12_13 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                # update ctr
                self.ctr12 += 1
                # compute x_12_23
                x_12_23 = x_12 ^ x_12_12 ^ x_12_13
                # store generated shares 
                self.shares_of_l2_norm_shares[client_id][0] = (x_12_12, x_12_13, x_12_23)
                # send (x_12_23,x_12_13) to S_3
                return (x_12_23, x_12_13)

            else: # generate boolean shares of x_13
                x_13 = self.y_share_t1[client_id][1]
                # generate x_13_12 
                key13_bytes = self.key13.to_bytes(self.num_bytes, 'big')
                ctr13_bytes = self.ctr13.to_bytes(self.num_bytes, 'big')
                hmac_obj = hmac.HMAC(key13_bytes, hashes.SHA256())
                hmac_obj.update(ctr13_bytes)
                x_13_12 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                # update ctr
                self.ctr13 += 1
                # generate x_13_13
                ctr13_bytes = self.ctr13.to_bytes(self.num_bytes, 'big')
                hmac_obj = hmac.HMAC(key13_bytes, hashes.SHA256())
                hmac_obj.update(ctr13_bytes)
                x_13_13 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                # update ctr
                self.ctr13 += 1
                # compute x_13_23 
                x_13_23 = x_13 ^ x_13_12 ^ x_13_13
                # store generated shares
                self.shares_of_l2_norm_shares[client_id][1] = (x_13_12, x_13_13, x_13_23)
                # send (x_13_12,x_13_23) to S_2
                return (x_13_12, x_13_23)

        elif self.id == 2:
            assert server_id == '1' or server_id == '3'
            if server_id == '1': # generate boolean shares of x_12
                x_12 = self.y_share_t1[client_id][0]
                # generate x_12_12
                key12_bytes = self.key12.to_bytes(self.num_bytes, 'big')
                ctr12_bytes = self.ctr12.to_bytes(self.num_bytes, 'big')
                hmac_obj = hmac.HMAC(key12_bytes, hashes.SHA256())
                hmac_obj.update(ctr12_bytes)
                x_12_12 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                # update ctr
                self.ctr12 += 1
                # generate x_12_13
                ctr12_bytes = self.ctr12.to_bytes(self.num_bytes, 'big')
                hmac_obj = hmac.HMAC(key12_bytes, hashes.SHA256())
                hmac_obj.update(ctr12_bytes)
                x_12_13 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                # update ctr
                self.ctr12 += 1
                # compute x_12_23
                x_12_23 = x_12 ^ x_12_12 ^ x_12_13
                # store generated shares 
                self.shares_of_l2_norm_shares[client_id][0] = (x_12_12, x_12_13, x_12_23)
                # send H(x_12_23||x_12_13) to S_3
                input_bytes = x_12_23.to_bytes(self.num_bytes, 'big')
                input_bytes += x_12_13.to_bytes(self.num_bytes, 'big')
                digest = hashes.Hash(hashes.SHA256())
                digest.update(input_bytes)
                output_bytes = digest.finalize()
                return output_bytes

            else: # generate boolean shares of x_23
                x_23 = self.y_share_t1[client_id][1]
                # generate x_23_12 
                key23_bytes = self.key23.to_bytes(self.num_bytes, 'big')
                ctr23_bytes = self.ctr23.to_bytes(self.num_bytes, 'big')
                hmac_obj = hmac.HMAC(key23_bytes, hashes.SHA256())
                hmac_obj.update(ctr23_bytes)
                x_23_12 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                # update ctr
                self.ctr23 += 1
                # generate x_23_13 
                ctr23_bytes = self.ctr23.to_bytes(self.num_bytes, 'big')
                hmac_obj = hmac.HMAC(key23_bytes, hashes.SHA256())
                hmac_obj.update(ctr23_bytes)
                x_23_13 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                # update ctr
                self.ctr23 += 1
                # compute x_23_23
                x_23_23 = x_23 ^ x_23_12 ^ x_23_13
                # store generated shares
                self.shares_of_l2_norm_shares[client_id][2] = (x_23_12, x_23_13, x_23_23)
                # send (x_23_12,x_23_13) to S_1
                return (x_23_12, x_23_13)

        else:
            assert server_id == '1' or server_id == '2'
            if server_id == '1': # generate boolean shares of x_13
                x_13 = self.y_share_t1[client_id][1]
                # generate x_13_12 
                key13_bytes = self.key13.to_bytes(self.num_bytes, 'big')
                ctr13_bytes = self.ctr13.to_bytes(self.num_bytes, 'big')
                hmac_obj = hmac.HMAC(key13_bytes, hashes.SHA256())
                hmac_obj.update(ctr13_bytes)
                x_13_12 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                # update ctr
                self.ctr13 += 1
                # generate x_13_13
                ctr13_bytes = self.ctr13.to_bytes(self.num_bytes, 'big')
                hmac_obj = hmac.HMAC(key13_bytes, hashes.SHA256())
                hmac_obj.update(ctr13_bytes)
                x_13_13 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                # update ctr
                self.ctr13 += 1
                # compute x_13_23
                x_13_23 = x_13 ^ x_13_12 ^ x_13_13
                # store generated shares 
                self.shares_of_l2_norm_shares[client_id][1] = (x_13_12, x_13_13, x_13_23)
                # send H(x_13_12||x_13_23) to S_2
                input_bytes = x_13_12.to_bytes(self.num_bytes, 'big')
                input_bytes += x_13_23.to_bytes(self.num_bytes, 'big')
                digest = hashes.Hash(hashes.SHA256())
                digest.update(input_bytes)
                output_bytes = digest.finalize()
                return output_bytes

            else: # generate boolean shares of x_23
                x_23 = self.y_share_t1[client_id][0]
                # generate x_23_12 
                key23_bytes = self.key23.to_bytes(self.num_bytes, 'big')
                ctr23_bytes = self.ctr23.to_bytes(self.num_bytes, 'big')
                hmac_obj = hmac.HMAC(key23_bytes, hashes.SHA256())
                hmac_obj.update(ctr23_bytes)
                x_23_12 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                # update ctr
                self.ctr23 += 1
                # generate x_23_13 
                ctr23_bytes = self.ctr23.to_bytes(self.num_bytes, 'big')
                hmac_obj = hmac.HMAC(key23_bytes, hashes.SHA256())
                hmac_obj.update(ctr23_bytes)
                x_23_13 = int.from_bytes(hmac_obj.finalize(), 'big') & self.mask
                # update ctr
                self.ctr23 += 1
                # compute x_23_23
                x_23_23 = x_23 ^ x_23_12 ^ x_23_13
                # store generated shares
                self.shares_of_l2_norm_shares[client_id][2] = (x_23_12, x_23_13, x_23_23)
                # send H(x_23_12||x_23_13) to S_1
                input_bytes = x_23_12.to_bytes(self.num_bytes, 'big')
                input_bytes += x_23_13.to_bytes(self.num_bytes, 'big')
                digest = hashes.Hash(hashes.SHA256())
                digest.update(input_bytes)
                output_bytes = digest.finalize()
                return output_bytes
            
    # receive boolean shares of l2 norm shares
    def receive_shares_of_l2norm_shares(self, shares : Tuple[int], digest : bytes, client_id :str) -> bool:
        assert len(shares) == 2
        # check consistency
        input_bytes = shares[0].to_bytes(self.num_bytes, 'big')
        input_bytes += shares[1].to_bytes(self.num_bytes, 'big')
        digest_obj = hashes.Hash(hashes.SHA256())
        digest_obj.update(input_bytes)
        if digest != digest_obj.finalize():
            print("received boolean shares of l2 norm shares are inconsistent!")
            return False
        # store the shares
        if self.id == 1: # receive shares (x_23_12,x_23_13)
            self.shares_of_l2_norm_shares[client_id][2] = shares
        elif self.id == 2: # receive shares (x_13_12,x_13_23)
            self.shares_of_l2_norm_shares[client_id][1] = shares
        else: # receive shares (x_12_23,x_12_13)
            self.shares_of_l2_norm_shares[client_id][0] = shares
        
        return True
    
    # receive arithmetic shares of l2 norm bound 
    def receive_shares_of_l2norm_bound(self, shares : Tuple[int,int]) -> bool:
        self.shares_of_l2_norm_bound = shares
        return True

    # compute the difference between norm and the bound 
    def compute_difference_between_norm_and_bound(self, client_id :str) -> bool:
        assert client_id in self.y_reduced_share_t1.keys()
        d_1 = self.y_reduced_share_t1[client_id][0] - self.shares_of_l2_norm_bound[0]
        d_2 = self.y_reduced_share_t1[client_id][1] - self.shares_of_l2_norm_bound[1]
        self.shares_of_difference_between_norm_and_bound[client_id] = (d_1, d_2)
        return True

    # return shares of difference for checking consistency 
    def return_share_of_difference(self, client_id : str) -> int:
        assert client_id in self.shares_of_difference_between_norm_and_bound.keys()
        if self.id == 1:
            return self.shares_of_difference_between_norm_and_bound[client_id][0]
        else:
            return self.shares_of_difference_between_norm_and_bound[client_id][1]

    # recover difference 
    def recover_difference(self, client_id : str, receive_share : int) -> int:
        recovered_d = self.shares_of_difference_between_norm_and_bound[client_id][0] + \
                            self.shares_of_difference_between_norm_and_bound[client_id][1] + \
                            receive_share 
        print("\033[34min function recover_difference, shares of d:\033[0m")
        print(self.shares_of_difference_between_norm_and_bound[client_id][0],self.shares_of_difference_between_norm_and_bound[client_id][1],receive_share)
        self.difference_between_norm_and_bound[client_id] = recovered_d
        return recovered_d
    
    # check norm bound 
    def check_norm_bound(self, client_id : str, receive_difference : int) -> Tuple[bool, bool]:
        consistency_result = True if receive_difference == self.difference_between_norm_and_bound[client_id] else False
        if_violation_result = True if receive_difference >= 0 else False
        print("\033[34mself.id:",self.id,"difference:\033[0m",receive_difference)
        return (consistency_result, if_violation_result)

if __name__ == "__main__":
    ip = '127.0.0.1'
    port = 9123
    server = Server((ip, port), MyServerRequestHandler)
    print("server is running...")
    server.serve_forever()
                    













        