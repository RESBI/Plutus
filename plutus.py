# Plutus Bitcoin Brute Forcer
# Made by Isaac Delly
# https://github.com/Isaacdelly/Plutus

from fastecdsa import keys, curve
from ellipticcurve.privateKey import PrivateKey
import platform
import multiprocessing
import hashlib
import binascii
import os
import sys
import time

DATABASE = r'database/11_13_2022/'

def generate_private_key():
    return binascii.hexlify(os.urandom(32)).decode('utf-8').upper()

def private_key_to_public_key(private_key, fastecdsa):
    #if fastecdsa:
    key = keys.get_public_key(int('0x' + private_key, 0), curve.secp256k1)
    return '04' + (hex(key.x)[2:] + hex(key.y)[2:]).zfill(128)
    #else:
    #    pk = PrivateKey().fromString(bytes.fromhex(private_key))
    #    return '04' + pk.publicKey().toString().hex().upper()

def public_key_to_address(public_key):
    output = []
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    var = hashlib.new('ripemd160')
    encoding = binascii.unhexlify(public_key.encode())
    var.update(hashlib.sha256(encoding).digest())
    var_encoded = ('00' + var.hexdigest()).encode()
    digest = hashlib.sha256(binascii.unhexlify(var_encoded)).digest()
    var_hex = '00' + var.hexdigest() + hashlib.sha256(digest).hexdigest()[0:8]
    count = [char != '0' for char in var_hex].index(True) // 2
    n = int(var_hex, 16)
    while n > 0:
        n, remainder = divmod(n, 58)
        output.append(alphabet[remainder])
    for i in range(count): output.append(alphabet[0])
    return ''.join(output[::-1])

def private_key_to_wif(private_key):
    digest = hashlib.sha256(binascii.unhexlify('80' + private_key)).hexdigest()
    var = hashlib.sha256(binascii.unhexlify(digest)).hexdigest()
    var = binascii.unhexlify('80' + private_key + var[0:8])
    alphabet = chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = pad = 0
    result = ''
    for i, c in enumerate(var[::-1]): value += 256**i * c
    while value >= len(alphabet):
        div, mod = divmod(value, len(alphabet))
        result, value = chars[mod] + result, div
    result = chars[value] + result
    for c in var:
        if c == 0: pad += 1
        else: break
    return chars[0] * pad + result

def main(database, cpuid, args):
    while True:
        time_begin = time.time() 
        # Detailly perf the program. Usually the private_key_to_public_key function takes 99% of time. 
        # It is really out of my expectation because I thought the address checking will take the big part. 
        #a = 0
        #b = 0
        #c = 0
        #d = 0
        #e = 0
        for i in range(10000):
            #a += time.time()
            private_key = generate_private_key()
            #b += time.time()
            public_key = private_key_to_public_key(private_key, args['fastecdsa']) 
            #c += time.time()
            address = public_key_to_address(public_key)
            #d += time.time() 

            tail = address[-args['substring']:]
            #head = address[:args['substring']]
            rest = address[:-args['substring']]
            if tail in database.keys(): 
                if rest in database[tail]: 
                    print("Found! {}".format(address))
                    with open('plutus.txt', 'a') as plutus:
                        plutus.write('hex private key: ' + str(private_key) + '\n' +
                                     'WIF private key: ' + str(private_key_to_wif(private_key)) + '\n'
                                     'public key: ' + str(public_key) + '\n' +
                                     'uncompressed address: ' + str(address) + '\n\n')
            #e += time.time()
        #delta1 = (b - a) / 10000
        #delta2 = (c - b) / 10000
        #delta3 = (d - c) / 10000
        #delta4 = (e - d) / 10000

        time_end = time.time()
        delta_time = time_end - time_begin
        #print("{}:\t{} A/s\t{}\t{}\t{}\t{}".format(cpuid, round(10000 / delta_time, 2), delta1, delta2, delta3, delta4))
        print("{}:\t{} A/s".format(cpuid, round(10000 / delta_time, 2)))


def print_help():
    print('''Plutus homepage: https://github.com/Isaacdelly/Plutus
Plutus QA support: https://github.com/Isaacdelly/Plutus/issues


Speed test: 
execute 'python3 plutus.py time', the output will be the time it takes to bruteforce a single address in seconds


Quick start: run command 'python3 plutus.py'

By default this program runs with parameters:
python3 plutus.py substring=10

substring: when address was generated, the program will first look at the tail with certain length of it, the length was determined by this parameter. The length was set to 10 by default, the improvement of performance by changing this parameter wasn't detailed studied yet. This parameter must be smaller than 27, because the length of a shortest BTC address 
was 26, and bigger than 0, otherwize no addresses will pass the first check. 

cpu_count: number of cores to run concurrently. More cores = more resource usage but faster bruteforcing. Omit this parameter to run with the maximum number of cores''')
    sys.exit(0)


def start(): 
    args = {
        'verbose': 0,
        'substring': 10,
        'fastecdsa': platform.system() in ['Linux', 'Darwin'],
        'cpu_count': multiprocessing.cpu_count(),
    }
    
    for arg in sys.argv[1:]:
        command = arg.split('=')[0]
        if command == 'help':
            print_help()
        elif command == 'time':
            timer(args)
        elif command == 'cpu_count':
            cpu_count = int(arg.split('=')[1])
            if cpu_count > 0 and cpu_count <= multiprocessing.cpu_count():
                args['cpu_count'] = cpu_count
            else:
                print('invalid input. cpu_count must be greater than 0 and less than or equal to ' + str(multiprocessing.cpu_count()))
                sys.exit(-1)
        elif command == 'verbose':
            verbose = arg.split('=')[1]
            if verbose in ['0', '1']:
                args['verbose'] = verbose
            else:
                print('invalid input. verbose must be 0(false) or 1(true)')
                sys.exit(-1)
        elif command == 'substring':
            substring = int(arg.split('=')[1])
            if substring > 0 and substring < 30:
                args['substring'] = substring
            else:
                print('invalid input. substring must be greater than 0 and less than 27')
                sys.exit(-1)
        else:
            print('invalid input: ' + command  + '\nrun `python3 plutus.py help` for help')
            sys.exit(-1)
    
    print('reading database files...')
    database = {}
    database_filenames = os.listdir(DATABASE)
    for file_index in range(len(database_filenames)):
        filename = database_filenames[file_index]
        print("{}/{}\t{}".format(file_index + 1, len(database_filenames), filename))
        with open(DATABASE + filename) as file:
            for address in file:
                address = address.strip()
                #if address.startswith('1'):
                tail = address[-args['substring']:]
                #head = address[:args['substring']]
                # Only storing the rest part of an address to save memory... althought pretty unnecessary. 
                rest = address[:-args['substring']]
                #database.add(tail)
                if tail in database.keys(): 
                    database[tail].add(rest) 
                else: 
                    database[tail] = set({rest})

    print('DONE')

    print('database size: ' + str(len(database.keys())))
    print('processes spawned: ' + str(args['cpu_count']))
    
    for cpu in range(args['cpu_count']):
        multiprocessing.Process(target = main, args = (database, cpu, args)).start()

# Convenient to be cythonize
if __name__ == '__main__':
    start() 
