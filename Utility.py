import os
import sys
import math 
import time 
import socket 
import numpy as np
from typing import List, Tuple, Dict

def read_arbitrary_bit_length(file, num_bytes, count):
    """
    Read `count` integers from the file, each with `num_bytes` bytes.

    Args:
    - file: File object to read from.
    - num_bytes: Number of bytes per integer.
    - count: Number of integers to read.

    Returns:
    - List of integers represented by `num_bytes`.
    """
    # Read raw data from the file
    raw_data = file.read(num_bytes * count)
    if len(raw_data) < num_bytes * count:
        raise ValueError("Insufficient data in file to read the required number of integers")

    # Convert each block of `num_bytes` into an integer
    integers = [
        int.from_bytes(raw_data[i * num_bytes: (i + 1) * num_bytes], byteorder=sys.byteorder)
        for i in range(count)
    ]
    return integers

def process_chunk(start_idx, end_idx, deltas, epsilon_chunk, gammas_chunk, powers_of_2, id, mask):
    """
    Process a chunk of data dimensions for a single client.
    """
    chunk_size = end_idx - start_idx
    final_shares_chunk = np.zeros((chunk_size, 2), dtype=np.int64)

    for i in range(chunk_size):
        neg_factors = np.where(deltas[start_idx + i], -1, 1)  # Vectorized neg_factor
        power_neg_factors = powers_of_2 * neg_factors

        if id == 1:
            epsilon12 = epsilon_chunk[i, :, 0]
            epsilon13 = epsilon_chunk[i, :, 1]
            final_shares_chunk[i, 0] = np.sum(power_neg_factors * epsilon12) & mask
            final_shares_chunk[i, 1] = np.sum(power_neg_factors * epsilon13) & mask
        elif id == 2:
            epsilon12 = epsilon_chunk[i, :, 0]
            epsilon23 = epsilon_chunk[i, :, 1]
            gamma_row = gammas_chunk[start_idx + i]
            final_shares_chunk[i, 0] = np.sum(power_neg_factors * epsilon12) & mask
            final_shares_chunk[i, 1] = np.sum(power_neg_factors * (epsilon23 + gamma_row)) & mask
        else:  # id == 3
            epsilon23 = epsilon_chunk[i, :, 0]
            epsilon13 = epsilon_chunk[i, :, 1]
            gamma_row = gammas_chunk[start_idx + i]
            final_shares_chunk[i, 0] = np.sum(power_neg_factors * (epsilon23 + gamma_row)) & mask
            final_shares_chunk[i, 1] = np.sum(power_neg_factors * epsilon13) & mask

    return final_shares_chunk

def connect_with_retry(host, port, retry_interval=5):
    """
    Continuously tries to connect to the server until successful.

    :param host: The server's hostname or IP address
    :param port: The server's port number
    :param retry_interval: Time to wait (in seconds) before retrying
    """
    while True:
        try:
            # Create a socket object
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                print(f"Trying to connect to {host}:{port}...")
                s.connect((host, port))
                print(f"Successfully connected to {host}:{port}")
                return  # Exit the function once connected
        except ConnectionRefusedError as e:
            print(f"Connection refused: {e}")
            print(f"Retrying in {retry_interval} seconds...")
            time.sleep(retry_interval)  # Wait before retrying
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            print(f"Retrying in {retry_interval} seconds...")
            time.sleep(retry_interval)  # Wait before retrying

# a function to receive the exact number of bytes from the socket
def recv_exactly(sock, num_bytes):
    """Receive exactly `num_bytes` from the socket."""
    data = b''
    while len(data) < num_bytes:
        chunk = sock.recv(num_bytes - len(data))
        if not chunk:  # Connection closed or error
            raise ConnectionError("Socket connection closed before receiving expected data.")
        data += chunk
    return data


# extract boolean shares from scalar value, return a list 
def extract_boolean_shares(value : int, ring_size : int) -> List[int]:
    assert value <= (pow(2, ring_size) - 1) 
    boolean_shares = ''
    for i in range(ring_size):
        x_i = value & 1
        value >>= 1
        boolean_shares = boolean_shares + str(x_i)

    return boolean_shares

# get two's complement representation of an integer
def get_2complement_representation(value : int, ring_size : int) -> str:
    assert value <= (pow(2, ring_size) -1) 
    result = ''
    for i in range(ring_size):
        x_i = value & 1
        value >>= 1
        result = str(x_i) + result

    return result

# check share consistency 
def check_share_consistency(shares_S1 : Tuple[int], shares_S2 : Tuple[int], 
                            shares_S3 : Tuple[int]) -> bool:
    if shares_S1[0] == shares_S2[0] and shares_S1[1] == shares_S3[1] and shares_S2[1] == shares_S3[0]:
        return True
    else:
        return False
    
# compute l2-norm 
def compute_l2_norm(data : List[int]) -> int:
    l2_norm = 0
    data_dimension = len(data)
    for i in range(data_dimension):
        l2_norm = l2_norm + pow(data[i], 2)
    
    return l2_norm

# boolean binary string adder
def rjust_length(s1, s2, fill='0'):
    l1, l2 = len(s1), len(s2)
    if l1 > l2:
        s2 = s2.rjust(l1, fill)
    elif l2 > l1:
        s1 = s1.rjust(l2, fill)
    return (s1, s2)

def get_input():
    bits_a = input('input your first binary string  ')
    bits_b = input('input your second binary string ')
    return rjust_length(bits_a, bits_b)

def xor(bit_a, bit_b):
    A1 = bit_a and (not bit_b)
    A2 = (not bit_a) and bit_b
    return int(A1 or A2)

def half_adder(bit_a, bit_b):
    return (xor(bit_a, bit_b), bit_a and bit_b)

def full_adder(bit_a, bit_b, carry=0):
    sum1, carry1 = half_adder(bit_a, bit_b)
    sum2, carry2 = half_adder(sum1, carry)
    return (sum2, carry1 or carry2)

def binary_string_adder(bits_a, bits_b):
    carry = 0
    result = ''
    for i in range(len(bits_a)-1 , -1, -1):
        summ, carry = full_adder(int(bits_a[i]), int(bits_b[i]), carry)
        result += str(summ)
    result += str(carry)
    return result[::-1]

# generate random common keys and PRF counters, simulation of a SMPC protocol
def setup(num_bytes : int) -> Dict[str, List[Tuple]]:
    setup_materials = {'keys':[], 'PRF_counters':[]}
    k12 = os.urandom(num_bytes)
    k13 = os.urandom(num_bytes)
    k23 = os.urandom(num_bytes)
    kS  = os.urandom(num_bytes)

    ctr12 = int.from_bytes(os.urandom(num_bytes), 'big')
    ctr13 = int.from_bytes(os.urandom(num_bytes), 'big')
    ctr23 = int.from_bytes(os.urandom(num_bytes), 'big')
    ctrS  = int.from_bytes(os.urandom(num_bytes), 'big')

    keys_S1 = (k12, k13, kS)
    setup_materials['keys'].append(keys_S1)
    keys_S2 = (k12, k23, kS)
    setup_materials['keys'].append(keys_S2)
    keys_S3 = (k23, k13, kS)
    setup_materials['keys'].append(keys_S3)

    ctrs_S1 = [ctr12, ctr13, ctrS]
    setup_materials['PRF_counters'].append(ctrs_S1)
    ctrs_S2 = [ctr12, ctr23, ctrS]
    setup_materials['PRF_counters'].append(ctrs_S2)
    ctrs_S3 = [ctr23, ctr13, ctrS]
    setup_materials['PRF_counters'].append(ctrs_S3)

    return setup_materials

def int_to_twos_complement(n, num_bits, order_reversed=False):
    """Returns the two's complement binary representation of n using num_bits."""
    if n >= 0:
        # For non-negative numbers, just return the binary format with the desired number of bits
         bit_string = format(n, f'0{num_bits}b')
    else:
        # Compute two's complement for negative numbers
        bit_string = format((1 << num_bits) + n, f'0{num_bits}b')  # Adding n (a negative number) to 2^num_bits
    if order_reversed == True:
        bit_string = ''.join(reversed(bit_string))
    
    return bit_string
    
def int_from_twos_complement(bit_string, num_bits=32):
    unsigned = int(bit_string, 2)
    sign_mask = 1 << (num_bits - 1)  
    bits_mask = sign_mask - 1        
    return (unsigned & bits_mask) - (unsigned & sign_mask)

def twos_complement_bits_required(value):
    if value == 0:
        return 1  # Need at least 1 bit to represent 0
    elif value > 0:
        # For positive numbers, just find the number of bits required to represent the value in binary
        return math.ceil(math.log2(value + 1)) + 1  # +1 for the sign bit
    else:
        # For negative numbers, we use the two's complement representation, which requires more bits
        return math.ceil(math.log2(abs(value))) + 1  # +1 to include the sign bit
    
# def binary_adder(a_str, b_str):
#     """
#     Adds two binary numbers represented as strings of '0' and '1'.
    
#     Parameters:
#     a_str (str): First binary number as a string (e.g., '1011').
#     b_str (str): Second binary number as a string (e.g., '1101').
    
#     Returns:
#     result (str): Sum of the binary numbers as a string.
#     carry_out (int): Final carry-out.
#     """
#     # Ensure both binary strings have the same length by padding with '0's
#     max_len = max(len(a_str), len(b_str))
#     a_str = a_str.zfill(max_len)  # Pad with leading zeros
#     b_str = b_str.zfill(max_len)  # Pad with leading zeros

#     carry_in = 0
#     result = []

#     # Loop through each bit (starting from least significant)
#     for a, b in zip(reversed(a_str), reversed(b_str)):
#         a_bit = int(a)  # Convert from char to int
#         b_bit = int(b)  # Convert from char to int
#         sum_bit, carry_out = full_adder(a_bit, b_bit, carry_in)
#         result.insert(0, str(sum_bit))  # Insert sum at the beginning as string
#         carry_in = carry_out  # Carry-out becomes carry-in for the next bit

#     # If there is a final carry-out, add it to the result
#     if carry_out:
#         result.insert(0, str(carry_out))

#     return ''.join(result), carry_out

def carry_lookahead_adder(x : str, y : str) -> str:
    length = max(len(x), len(y))
    x = x + '0' * (length - len(x))
    y = y + '0' * (length - len(y)) 
    carries = [0]
    sum = []
    for i in range(length):
        g_i_minus_1 = int(x[i]) & int(y[i])
        p_i_minus_1 = int(x[i]) ^ int(y[i])
        carries.append(g_i_minus_1 ^ (p_i_minus_1 & carries[i]))
        sum.append(p_i_minus_1 ^ carries[i])
    result = ''
    for i in range(len(sum)):
        result = str(sum[i]) + result

    return result


if __name__ == '__main__':
    pass

