import os
import math
import time

# codes to compare the efficiency of two methods of modular operation
ring_size = 64
modulus = pow(2,ring_size)
mask = pow(2,ring_size) - 1
num_bytes = math.ceil(ring_size / 8)
a = pow(int.from_bytes(os.urandom(num_bytes), 'big'),20)
start1 = time.perf_counter()
result1 = a % modulus
end1 = time.perf_counter()
time1 = end1 - start1

start2 = time.perf_counter()
result2 = a & mask
end2 = time.perf_counter()
time2 = end2 - start2

print("result1:",result1,"time1:",time1*1000)
print("result2:",result2,"time2:",time2*1000)
