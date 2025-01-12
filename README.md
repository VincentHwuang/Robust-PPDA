# Robust-PPDA
codes of robust privacy-preserving data aggregation protocol

# requirements
Python>=3.8.19,
coloredlogs>=15.0.1,
cryptography>=42.0.8,
bitarray>=3.0.0

# run the codes
start four terminals, three of them are used to run codes of three servers, the last one is used to run codes for simulation of clients
## run codes of servers
on the first terminal: python NetCommServer(semi-honest).py -i 1 -p 9123 -n 5, 
on the second terminal: python NetCommServer(semi-honest).py -i 2 -p 9124 -n 5, 
on the third terminal: python NetCommServer(semi-honest).py -i 3 -p 9125 -n 5, 
read file 'NetCommServer(semi-honest).py' for the meaning of each parameter
## run codes for simulation of clients 
on the fourth terminal: python NetCommClient(semi-honest).py
