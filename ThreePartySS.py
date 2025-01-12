import os
import math
from typing import List, Tuple

class ThreePartySS(object):
    # type: "boolean" or "arithmetic", ring_size: the size \ell 
    # which denotes the ring \mathbb{Z}_{2^{\ell}} that RSS works over
    def __init__(self, type : str = "t1", ring_size : int = 1) -> None:
        self.type = type
        self.ring_size = ring_size
        self.mask = pow(2, ring_size)-1
        self.shares = []

    def share(self, secret : int) -> List[Tuple]:
        if self.type == "t1":
            return self.t1_share(secret=secret)
        else:
            return self.t2_share(secret=secret)

    def t1_share(self, secret : int) -> List[Tuple]:
        assert secret <= self.molulus
        num_byptes = math.ceil(self.ring_size / 8)
        share_12 = int.from_bytes(os.urandom(num_byptes), byteorder="big")
        share_13 = int.from_bytes(os.urandom(num_byptes), byteorder="big")
        share_23 = (secret - share_12 - share_13) & self.mask

        self.shares = [(share_12, share_13), (share_12, share_23), (share_23, share_13)]
        return self.shares
    
    def t2_share(self, secret : int) -> List[Tuple]:
        assert secret <= self.molulus
        num_byptes = math.ceil(self.ring_size / 8)
        m = int.from_bytes(os.urandom(num_byptes), byteorder="big")
        lambda_value = (m - secret) & self.mask
        lambda_12 = int.from_bytes(os.urandom(num_byptes), byteorder="big")
        lambda_13 = int.from_bytes(os.urandom(num_byptes), byteorder="big")
        lambda_23 = (lambda_value - lambda_12 - lambda_13) & self.mask

        self.shares = [(m, lambda_12, lambda_13), (m, lambda_12, lambda_23), (m, lambda_23, lambda_13)]
        return self.shares
    

