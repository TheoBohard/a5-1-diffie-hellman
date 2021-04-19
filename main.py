"""
ENSICAEN
6 Boulevard Marechal Juin
F-14050 Caen Cedex

Theo BOHARD & Ines BOURJIJ & Remy FOURREZ

This file is owned by ENSICAEN students. No portion of this
document may be reproduced, copied or revised without written
permission of the authors.

In this file you will find the different function to implement a5/1 stream cipher.
You will also find an implementation of diffie hellman key exchange for a secure exchange 
of the keys between two theoretical contributors that we can call Alice and Bob
"""

import random


def get_bit(value, n):
    """
    This function permit to get the bit n of a int

    :param value: The int where we want to get the bit
    :param n: The bit that we want to get
    :return: The value of the bit research
    """

    return value >> n & 1


def set_bit(value, n, bit):
    """
    This function permit to set the bit n of a int

    :param value: The int where we want to set the bit
    :param n: The bit that we want to set
    :param bit: The value of the bit that we want to set (0/1)
    :return: The int with the bit that we want to set modified
    """

    return value | (bit << n)

def generate_key():
    """
    This function permit to generate a 64 bit key

    :return: The 64 bit key in string format
    """

    return ''.join(random.choice(["0", "1"]) for i in range(64))


def is_binary_string(string):
    """
    This function permit to know if a string contains only 0 and 1

    :param string: The string that we want to check
    :return: 0 if the string contain other word/number, 1 otherwise
    """

    for char in string:
        if char not in '10':
            return 0
        else:
            pass
    return 1


def init_register():
    """
    This function permit to init the 3 lsfr register to 0

    :return: The register with values which equals to 0
    """

    lsfr1 = 0
    lsfr2 = 0
    lsfr3 = 0

    return lsfr1, lsfr2, lsfr3


def insert_key(key, lsfr1, lsfr2, lsfr3):
    """
    This function do the 64 turn where we shift the three lsfr and add the xor of tapped bit XOR key as bit 0

    :param key: The key
    :param lsfr1: The first lsfr
    :param lsfr2: The second lsfr
    :param lsfr3: The third lsfr
    :return: The three lsfr updated
    """

    for i in range(64):
        lsfr1 = lsfr1 << 1
        xor_lsfr1 = get_bit(lsfr1, 13) ^ get_bit(lsfr1, 16) ^ get_bit(lsfr1, 17) ^ get_bit(lsfr1, 18) ^ get_bit(key, i)
        lsfr1 = set_bit(lsfr1, 0, xor_lsfr1)

        lsfr2 = lsfr2 << 1
        xor_lsfr2 = get_bit(lsfr2, 20) ^ get_bit(lsfr2, 21) ^ get_bit(key, i)
        lsfr2 = set_bit(lsfr2, 0, xor_lsfr2)

        lsfr3 = lsfr3 << 1
        xor_lsfr3 = get_bit(lsfr3, 7) ^ get_bit(lsfr3, 20) ^ get_bit(lsfr3, 21) ^ get_bit(lsfr3, 22) ^ get_bit(key, i)
        lsfr3 = set_bit(lsfr3, 0, xor_lsfr3)

    return lsfr1, lsfr2, lsfr3


def insert_counter(counter, lsfr1, lsfr2, lsfr3):
    """
    This function do the 22 turn where we shift the three lsfr and add the xor of tapped bit XOR counter as bit 0

    :param counter: The counter of word

    :param lsfr1: The first lsfr
    :param lsfr2: The second lsfr
    :param lsfr3: The third lsfr
    :return: The three lsfr updated
    """

    for i in range(22):
        lsfr1 = lsfr1 << 1
        xor_lsfr1 = get_bit(lsfr1, 13) ^ get_bit(lsfr1, 16) ^ get_bit(lsfr1, 17) ^ get_bit(lsfr1, 18) ^ get_bit(counter,
                                                                                                                i)
        lsfr1 = set_bit(lsfr1, 0, xor_lsfr1)

        lsfr2 = lsfr2 << 1
        xor_lsfr2 = get_bit(lsfr2, 20) ^ get_bit(lsfr2, 21) ^ get_bit(counter, i)
        lsfr2 = set_bit(lsfr2, 0, xor_lsfr2)

        lsfr3 = lsfr3 << 1
        xor_lsfr3 = get_bit(lsfr3, 7) ^ get_bit(lsfr3, 20) ^ get_bit(lsfr3, 21) ^ get_bit(lsfr3, 22) ^ get_bit(counter,
                                                                                                               i)
        lsfr3 = set_bit(lsfr3, 0, xor_lsfr3)

    return lsfr1, lsfr2, lsfr3


def insert_char(lsfr1, lsfr2, lsfr3, letter):
    """
    This function permit to generate the keystream by shifting the three lsfr 8 time
    and adding the XOR of tapped bit XOR the character

    :param lsfr1: The first lsfr
    :param lsfr2: The second lsfr
    :param lsfr3: The third lsfr
    :param letter: The actual letter which we want to generate the keystream
    :return: The kestream
    """

    keystream = 0

    letter_ord = ord(letter)

    for i in range(8):

        if (get_bit(lsfr1, 8) + get_bit(lsfr2, 10) + get_bit(lsfr3, 10)) > 1:
            majority_bit = 1
        else:
            majority_bit = 0

        if majority_bit == get_bit(lsfr1, 8):
            lsfr1 = lsfr1 << 1
            xor_lsfr1 = get_bit(lsfr1, 13) ^ get_bit(lsfr1, 16) ^ get_bit(lsfr1, 17) ^ get_bit(lsfr1, 18) ^ get_bit(
                letter_ord, i)
            lsfr1 = set_bit(lsfr1, 0, xor_lsfr1)

        if majority_bit == get_bit(lsfr2, 10):
            lsfr2 = lsfr2 << 1
            xor_lsfr2 = get_bit(lsfr2, 20) ^ get_bit(lsfr2, 21) ^ get_bit(letter_ord, i)
            lsfr2 = set_bit(lsfr2, 0, xor_lsfr2)

        if majority_bit == get_bit(lsfr3, 10):
            lsfr3 = lsfr3 << 1
            xor_lsfr3 = get_bit(lsfr3, 7) ^ get_bit(lsfr3, 20) ^ get_bit(lsfr3, 21) ^ get_bit(lsfr3, 22) ^ get_bit(
                letter_ord, i)
            lsfr3 = set_bit(lsfr3, 0, xor_lsfr3)

        keystream = set_bit(keystream, i, get_bit(lsfr1, 18) ^ get_bit(lsfr2, 21) ^ get_bit(lsfr3, 22))

    return keystream


def get_letter_encrypted_decrypted(keystream, letter):
    """
    This function permit to encrypt or decrypt a letter

    :param keystream: The generated keystream
    :param letter: The letter that we want to encrypt/decrypt
    :return: The letter encrypted/decrypted
    """

    letter_ord = ord(letter)

    bin_str = ""

    for i in range(8):
        bin_str += str(get_bit(keystream, i) ^ get_bit(letter_ord, i))

    return chr(int(bin_str[::-1], 2))


def encrypt(word, key):
    """
    This function permit to encrypt a word

    :param word: The word that we want to encrypt
    :param key: The key that we want to use
    :return: The word encrypted
    """

    word_encrypted = ""
    counter = 0

    for i in range(len(word)):
        lsfr1, lsfr2, lsfr3 = init_register()

        lsfr1, lsfr2, lsfr3 = insert_key(key, lsfr1, lsfr2, lsfr3)

        lsfr1, lsfr2, lsfr3 = insert_counter(counter, lsfr1, lsfr2, lsfr3)

        keystream = insert_char(lsfr1, lsfr2, lsfr3, word[i])

        word_encrypted += get_letter_encrypted_decrypted(keystream, word[i])
        counter = counter + 1

    return word_encrypted


def decrypt(word_encrypted, key):
    """
    This function permit to decrypt a word

    :param word_encrypted: The word that we want to decrypt
    :param key: The key that we want to use
    :return: The word decrypted
    """

    word_decrypted = ""
    counter = 0

    for i in range(len(word_encrypted)):
        lsfr1, lsfr2, lsfr3 = init_register()
        lsfr1, lsfr2, lsfr3 = insert_key(key, lsfr1, lsfr2, lsfr3)
        lsfr1, lsfr2, lsfr3 = insert_counter(counter, lsfr1, lsfr2, lsfr3)
        keystream = insert_char(lsfr1, lsfr2, lsfr3, word_encrypted[i])
        word_decrypted += get_letter_encrypted_decrypted(keystream, word_encrypted[i])
        counter = counter + 1

    return word_decrypted

def square_and_multiply(a,k,n):
    """ 
    This function permit to do a quick exponentiation

    :param a: The value
    :param k: The exponant
    :param n: The value of the modulo
    :return: The result of the exponentiation
    """
    n = abs(n)
    h = 1

    bin_k = bin(k)

    for i in range(1, len(bin_k)):
        h = (h*h)%n

        if bin_k[i] == '1':
            h = (h*a)%n

    return h

def miller_rabin(n,d):
    """
    This function permit to do a primality test

    :param n: The value that we want to test
    :param d: A integer greater than 1
    :return: True if its a primal number, False otherwise
    """

    b = 0
    r = n - 1

    while r % 2 == 0:
        b += 1
        r = r // 2

    if n <= 0:
        return False

    if n <= 3 :
        return True


    for i in range(1, d):

        a = random.randint(2, (n-1))

        #Si a vaut n-1 ou 1 le test est positif
        a = square_and_multiply(int(a), int(r), int(n))
        if a != 1 and a != n-1:
            k = 1

            while k < b and a != n-1:
                a = square_and_multiply(a,2,n)
                k += 1
                if a == 1:
                    return False

            if a != n-1:
                return False

    return True

def generate_prime(k,d):
    """
    This function permit to generate a prime number 

    :param k: The number of bit that we want
    :param d: A integer greater than 1
    :return: The prime number in int format
    """

    def first_test(val):
        firstPrime = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79,
                      83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,149, 151, 157, 163, 167, 173,
                      179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269,
                      271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373,
                      379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439]

        if val > 439 :

            for i in firstPrime:
                if val%i == 0:
                    return False

        return True


    min = 2**(k-1) + 1
    max = (2**k) - 1

    while True:
        val = random.randint(min, max)
        if first_test(val):

            if miller_rabin(val, d):
                return val
def euclid(a,b):
    """ 
    This function permit to calculate Greatest Common Divisor of two number

    :param a: The first number
    :param b: The second number
    :return: The Greatest Common Divisor of the two number
    """

    if b < 0:
        b = -b

    while b!=0 :
        tmp = a
        a = b
        b = tmp%b

    return a

def naive_euler_function(n):
    """
    This function permit to calculate Euler's indicator 

    :param n: The number we want to calculate Euler's indicator
    :return: The Euler's indcator
    """
    count = 0

    for i in range(n):
        if euclid(i, n) == 1:
            count += 1

    return count

def order(a,n):
    """
    This function permit to calculate the order of two number

    :param a: The first number
    :param n: The second number
    :return: The order
    """

    if euclid(a,n) != 1:
        return 0

    i = 1
    while((a**i)%n != 1):
        i += 1

    return i

def generator(n):
    """
    This function permit to calculate the generator of a number

    :param n: The number
    :return: The value of the generator
    """

    fi = naive_euler_function(n)

    for i in range(1, n):
        if order(i, n) == fi:
            return i

    return 0


key_loaded = 0

# Alice et Bob se mettent d'accord sur un nombre premier commun, nomme p
print("a est transmit a Alice et Bob")
# p = generate_prime(512,10)
p = 7335465888343862968130285288842581941479997730776454051901203329440508367992945303835458008138016530970254318172965357391199557120543758438497838095839321

# Alice et Bob se mettent d'accord sur une base commune, nomme g
print("g est transmit a Alice et Bob")
# g = generator(p)
g = 3

# Alice va maintenant choisir un nombre secret nomme a
print("Bonjour ! Je suis Alice, je vais choisir aleatoirement un nombre secret nomme a")
a = random.randint(1, p - 2)

# Alice va donc ensuite calculer ga = g^a mod p qu'elle va envoyer a Bob, c'est donc la cle publique d'Alice
print("Je vais maintenant calculer ga = g^a mod p pour ensuite l'envoyer a Bob !")
ga = square_and_multiply(g, a, p)

# Bob va maintenant choisir un nombre secret nomme b
print("Bonjour ! Je suis Bob, je vais choisir aleatoirement un nombre secret nomme b")
b = random.randint(1, p - 2)

# Bob va donc ensuite calculer gb = g^b mod p qu'il va envoyer a Alice, c'est donc la cle publique de Bob
print("Je vais maintenant calculer gb = g^b mod p pour ensuite l'envoyer a Alice !")
gb = square_and_multiply(g, b, p)

# Alice peut donc maintenant calculer la cle secrete en faisant gb^a mod p
print("Maintenant que Bob m'a envoyer gb, je vais pouvoir calculer la cle secrete")
ba = square_and_multiply(gb, a, p)

# Bob peut donc maintenant calculer la cle secrete en faisant ab^b mod p
print("Alice m'ayant envoyer ga, je peut egalement calculer la cle secrete !")
ab = square_and_multiply(ga, b, p)
print("On remarque que la cle secrete n'a jamais etait transmise clairement ! Ce qui permet de se proteger contre Eve")

key = str(bin(ba))[2:66]
key_loaded = int(key, 2)

user_input_word = input("Veuillez entrer le mot/la phrase que vous voulez chiffrer : ")

word_encrypted = encrypt(user_input_word, key_loaded)

print("Mot chiffre : ", word_encrypted)

word_decrypted = decrypt(word_encrypted, key_loaded)

print("Mot dechiffre : ", word_decrypted)
