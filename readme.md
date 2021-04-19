## This document is about a "project" of cryptography for monetics for ENSICAEN

The authors of this PW is **Théo BOHARD** / **Inès BOURJIJ** / **Rémy FOURREZ**.

You will find a file named tp_crypto_final.py to execute it i advice you to use python3 instead of python because 
if you use python you will have to put "" to enter the word to encrypt

<code> python3 tp_crypto_final.py </code>


In the doc folder you will find an index.html which contains the documentation
of the different functions that we have created for this practical work.


You will also find three different type function :

* Bit manipulation functions
* A5/1 functions
* Diffie-Hellman functions 

And the main to use the different functions.

The practical work is not completely finished because our generator can't generate the generator for a big number like a 512 bits number. 

So we have decided to let our function, but put the implementation as commentary. 

Finally, we have decided to handle this problem using the two values that you have put in the practical work subject. 

The program sequence is started by making an exchange between two theoretical contributors (Alice and Bob). 
By doing that each one can calculate the private key, after we parse it to get a 64 bit, which will be injected in a5/1 cipher system.
After that the sequence will ask you to enter a word to encrypt you will see the word encrypted and after the program will decrypt it and display it to you.
