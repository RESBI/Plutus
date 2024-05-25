# Plutus Bitcoin Brute Forcer

A Bitcoin wallet collider that brute forces random wallet addresses

# Deviation From The Original Repo

## Removed some unused codes 

Removed supportance to Windows. You could recover it by modifying the code 

https://github.com/RESBI/Plutus/blob/57bcb63b2dd1bae0c13de51e31cea415b64039b5/plutus.py#L20-L26

## Display cracking rate 

While running, it prints `CPUID: ADDRESSRATE A/s` to the terminal, where `CPUID` is the worker's ID and `ADDRESSRATE A/s` stands for # of addresses was checked in one second on average. 

## Huge memory required 

It loads the whole database into memory. 

To use the original database, you need more than 20 GiB of RAM. 

# Like This Project? Give It A Star

[![Original Repo](https://img.shields.io/github/stars/Isaacdelly/Plutus.svg)](https://github.com/Isaacdelly/Plutus)
[![This Repo](https://img.shields.io/github/stars/RESBI/Plutus.svg)](https://github.com/RESBI/Plutus)

# Dependencies

<a href="https://www.python.org/downloads/">Python 3.8</a> or higher

Python modules listed in the <a href="/requirements.txt">requirements.txt<a/>

If you have a __Linux__ or __MacOS__ operating system, libgmp3-dev is required. If you have __Windows__ then this is not required. Install by running the command:
```
sudo apt-get install libgmp3-dev
```

# Installation

```
git clone https://github.com/RESBI/Plutus.git plutus
```
```
cd plutus && pip3 install -r requirements.txt
```

# Quick Start

```
python3 plutus.py
```

# Proof Of Concept

A private key is a secret number that allows Bitcoins to be spent. If a wallet has Bitcoins in it, then the private key will allow a person to control the wallet and spend whatever balance the wallet has. So this program attempts to find Bitcoin private keys that correlate to wallets with positive balances. However, because it is impossible to know which private keys control wallets with money and which private keys control empty wallets, we have to randomly look at every possible private key that exists and hope to find one that has a balance.

This program is essentially a brute forcing algorithm. It continuously generates random Bitcoin private keys, converts the private keys into their respective wallet addresses, then checks the balance of the addresses. If a wallet with a balance is found, then the private key, public key and wallet address are saved to the text file `plutus.txt` on the user's hard drive. The ultimate goal is to randomly find a wallet with a balance out of the 2<sup>160</sup> possible wallets in existence. 

# How It Works

32 byte hexidecimal strings are generated randomly using `os.urandom()` and are used as our private keys.

The private keys are converted into their respective public keys using the `fastecdsa` python library. This is the fastest library to perform secp256k1 signing. If you run this on Windows then `fastecdsa` is not supported, so instead we use `starkbank-ecdsa` to generate public keys. The public keys are converted into their Bitcoin wallet addresses using the `binascii` and `hashlib` standard libraries.

A pre-calculated database of every funded P2PKH Bitcoin address is included in this project. The generated address is searched within the database, and if it is found that the address has a balance, then the private key, public key and wallet address are saved to the text file `plutus.txt` on the user's hard drive.

This program also utilizes multiprocessing through the `multiprocessing.Process()` function in order to make concurrent calculations.

# Efficiency

| CPU Name     | # of workers | A/s of 1 worker | Total A/s | 
| :----------: | :----------: | :-------------: | :-------: |
| 2x E5-2696v3 | 72           | 300             | 21600     |
| R5-5600G     | 12           | 750             | 9000      |

Welcome to upload your performance data in the issue. 

# Database FAQ

An offline database is used to find the balance of generated Bitcoin addresses. Visit <a href="/database/">/database</a> for information.

# Parameters

This program has optional parameters to customize how it runs:

__help__: `python3 plutus.py help` <br />
Prints a short explanation of the parameters and how they work

__substring__: `python3 plutus.py substring=10`:
When address was generated, the program will first look at the tail with certain length of it, the length was determined by this parameter. The length was set to 10 by default, the improvement of performance by changing this parameter wasn't detailed studied yet. This parameter must be smaller than 27, because the length of a shortest BTC address 
was 26, and bigger than 0, otherwize no addresses will pass the first check. 

__cpu_count__: `python3 plutus.py cpu_count=1`: number of cores to run concurrently. More cores = more resource usage but faster bruteforcing. Omit this parameter to run with the maximum number of cores

By default the program runs using `python3 plutus.py substring=10` if nothing is passed.
  
# Expected Output

If a wallet with a balance is found, then all necessary information about the wallet will be saved to the text file `plutus.txt`. An example is:

>hex private key: 5A4F3F1CAB44848B2C2C515AE74E9CC487A9982C9DD695810230EA48B1DCEADD<br/>
>WIF private key: 5JW4RCAXDbocFLK9bxqw5cbQwuSn86fpbmz2HhT9nvKMTh68hjm<br/>
>public key: 04393B30BC950F358326062FF28D194A5B28751C1FF2562C02CA4DFB2A864DE63280CC140D0D540EA1A5711D1E519C842684F42445C41CB501B7EA00361699C320<br/>
>uncompressed address: 1Kz2CTvjzkZ3p2BQb5x5DX6GEoHX2jFS45<br/>

# Recent Improvements & TODO

<a href="https://github.com/RESBI/Plutus/issues">Create an issue</a> so I can add more stuff to improve

## Update the database

We could found the latest addresses here https://github.com/Pymmdrza/Rich-Address-Wallet/

## Improve the performance 

Really hard to. 

## Change the searching algorithm 

Maybe there's a better way to check the address? 

## Port to Xeon Phi 

Hard to, since slow cores and small memory. 
