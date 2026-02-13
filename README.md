# CryptorSFMT  

With that project i try to improve the original implementation of CryptorMT with the newer SFMT implementation.  
SFMT provides a higher performance, potentially better quality pseudo-random numbers and a much higher maximum periodicity.  
The longer periodicity itself is already interesting but it requires much larger generator arrays and with that allows much larger useful key's.  

Also CryptorSFMT now offers a new encryption method that uses an sbox to hide at least parts of the stream cipher behind an sbox.  
That method is much more computational heavy meaning its encryption/decryption times are significantly slower than just a simple xor with the stream cipher.  
But that should also make a potential brute-force attack more costly.  

A more detailed description of the used algorithm can be found in doc/Description.txt.  


## Usage

Like CryptorMT also CryptorSFMT can read/write from/to stdin and stdout.  
But in- and outfile can be explicetly named.  

Encrypting a file with a password:  

`cryptorsfmt -p 1234567890 -i alice\_in\_wonderland.txt -o alice\_in\_wonderland.txt.cpt`  
`cat alice\_in\_wonderland.txt | cryptormt -p 1234567890 > alice\_in\_wonderland.txt.cpt`  
`cryptorsfmt -p 1234567890 < alice\_in\_wonderland.txt > alice.txt.cpt`  

Encrypting a file with a keyfile: 

`cat alice\_in\_wonderland.txt | cryptorsfmt -k keyfile > alice\_in\_wonderland.txt.cpt`  

Compress and encrypt a file:

`gzip -c alice\_in\_wonderland.txt | cryptorsfmt -p 1234 > alice.gz.cpt`  

To Decrypt a file:  

`cryptorsfmt -d -p 1234567890 -i alice.txt.cpt -o alice.txt`  
`cryptorsfmt -d -p 1234567890 < alice.txt.cpt > alice.txt`  

Even encrypted file transfer over networks is possible (with constraints).  
First setup the receiver:  

`nc -nvlp 1234 | cryptorsfmt -d -p 1234 > alice.txt`  

Than the sender:  

`bar alice_in_wonderland.txt | cryptorsfmt -p 1234 | nc <receiver ip> 1234`  

The problem here is at this moment buffering prevents some processes from detecting an end-of-file.  
So once reports 100% for the sender than just hit Ctrl+C on the sender cli.  
That will start flushing all buffers and also ends the receiver process.  

To use the new mode a new switch was added.

Encryption in Mode 2:  

`cryptorsfmt -m 2 -p 1234567890 -i alice\_in\_wonderland.txt -o alice\_in\_wonderland.txt.cpt`  

Decryption in Mode 2:

`cryptorsfmt -m 2 -d -p 1234567890 -i alice\_in\_wonderland.txt -o alice\_in\_wonderland.txt.cpt`  

The Mode is not auto-detected.  
So it MUST be provided every time, otherwise CrpytorSFMT will default to Mode 1 which will "decrypt" with xor combination, which will lead to unreadable output.


## Installation

There is not a real installation required.  
Only the CryptorSFMT in an directory of your choice.  
To compile the source you can use one of the following commands depending on what compiler is available to you.  

`cd /path/to/compile_dir/`

`git clone https://github.com/user66352/CryptorSFMT`  

`cd CryptorSFMT`  

Inside the CryptorSFMT Directory run:  

`g++ -Wall -std=c++20 -O3 -msse2 -DHAVE_SSE2 -I./headers/ ./src/*.c ./src/*.cpp -o cryptorsfmt` 

or  

`clang++ -Wall -x c++ -std=c++20 -O3 -msse2 -DHAVE_SSE2 -I./headers/ ./src/*.c ./src/*.cpp -o cryptorsfmt` 

or 

`gcc -x c++ -Wall -std=c++20 -O3 -msse2 -fno-strict-aliasing -DHAVE_SSE2=1 -I./headers/ ./src/*.c ./src/*.cpp -o cryptorsfmt -lstdc++` 

That will create the required binary `cryptorsfmt` in directory /path/to/cryptorsfmt/CryptorSFMT.  


## Mentions  

This project uses additional libraries from other projects:  

SIMD-oriented Fast Mersenne Twister (SFMT) (permissive software license; see SFMT-LICENSE.txt in headers):  
https://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/SFMT/  

clipp.h for parsing command line arguments (MIT License):  
https://github.com/muellan/clipp  

SHA512 Algorithm (MIT License):  
https://github.com/pr0f3ss/SHA  
