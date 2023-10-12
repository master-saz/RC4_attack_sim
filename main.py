import pandas as pd
import numpy as np

"""
The attack is based on the following facts:
    1. For any byte x, using iv=01 FF x results in a keystream such that its first byte equals x+2 with high
    probability.
    
    2. The first keystream byte produced with iv=03 FF x is, with a noticeable probability, x+6+k[0], where
    k[0] denotes the first byte of the long-term key. Similarly, iv=04 FF x produces the first keystream
    byte equal to x+10+k[0]+k[1] with a noticeable probability.
    
    3. In general, for i ranging from 0 to 12, using iv=z FF x where z is the hexadecimal representation of
    i + 3 often produces the first keystream byte equal to x+d[i]+k[0]+k[1]+...+k[i], where d[i] is
    the constant 1 + 2 + . . . + (i + 3).
"""


def fact3(given_cipher, mrv_f1, k_list, given_iv, constant_d):
    # where mrv_f1 is the most repeated value obtained from fact 1.
    # where mrv_kn is the most repeated value obtained from k[n].

    # x-10
    given_iv = given_iv[len(given_iv) - 2:]
    iv_dec = int(given_iv, base=16)
    iv_dec = (iv_dec - constant_d) % 256

    cipher_dec_val = int(given_cipher, base=16)
    mrv_f1_dec_val = int(mrv_f1, base=16)

    mrv_kn_dec_val = 0
    for k_i in k_list:
        mrv_kn_dec_val -= int(k_i, base=16)

    # (c[0] XOR m[0]) - x - d[0] - k[0]
    result = (cipher_dec_val ^ mrv_f1_dec_val) - iv_dec - mrv_kn_dec_val
    result = (result + 256) % 256  # TODO to deal with negative values
    result = '0x{0:02x}'.format(result).upper()
    return result


def fact2_extra_operation(given_cipher, mrv_f1, mrv_kn, given_iv):
    # where mrv_f1 is the most repeated value obtained from fact 1.
    # where mrv_kn is the most repeated value obtained from k[n].

    # x-10
    given_iv = given_iv[len(given_iv) - 2:]
    iv_dec = int(given_iv, base=16)
    iv_dec = (iv_dec - 10) % 256

    cipher_dec_val = int(given_cipher, base=16)
    mrv_f1_dec_val = int(mrv_f1, base=16)
    mrv_kn_dec_val = int(mrv_kn, base=16)

    # (c[0] XOR m[0]) - x - 10 - k[0]
    result = (cipher_dec_val ^ mrv_f1_dec_val) - iv_dec - mrv_kn_dec_val
    result = (result + 256) % 256  # TODO to deal with negative values
    result = '0x{0:02x}'.format(result).upper()
    return result


def fact2_operation(given_cipher, mrv_f1, given_iv):
    # where mrv_f1 is the most repeated value obtained from fact 1.
    # x-6
    given_iv = given_iv[len(given_iv) - 2:]
    iv_dec = int(given_iv, base=16)
    iv_dec = (iv_dec - 6) % 256

    cipher_dec_val = int(given_cipher, base=16)
    mrv_f1_dec_val = int(mrv_f1, base=16)
    # (c[0] XOR m[0])-x-6
    result = (cipher_dec_val ^ mrv_f1_dec_val) - iv_dec
    result = (result + 256) % 256  #TODO to deal with negative values
    #print(result)
    result = '0x{0:02x}'.format(result).upper()
    return result


def fact1_byte_operation(given_cipher, given_iv):
    given_iv = given_iv[len(given_iv) - 2:]
    #print(iv)
    iv_dec = int(given_iv, base=16)
    iv_dec = (iv_dec + 2) % 256
    #print(iv_dec)
    cipher_dec_val = int(given_cipher, base=16)
    #print(cipher_dec_val)
    result = cipher_dec_val ^ iv_dec # c[0] XOR (x+2)
    #print(result)
    result = '0x{0:02x}'.format(result).upper()
    return result


def get_rest_of_k():
    """
    In general, for i ranging from 0 to 12, using iv=z FF x (where z is the hexadecimal representation of i+3)
    often produces the first keystream byte equal to x+d[i]+k[0]+k[1]+…+k[i] ,
    where d[i] is the constant 1+2+…+(i+3).
    """
    key_len = 13
    for i in range(2, key_len):  # from 2 to key length since we already have k0 and k1
        tmp = (i + 3) % 256
        z = '{0:02x}'.format(tmp).upper()
        x = ""  # get most repeated value?
        d = 0  # the constant d[i]
        for j in range(i + 4):  # +4 because it is until (i+3) in the sequence 1+2+…+(i+3)
            d += j
        # print(f"{i}:{d}")
        #print(z)

        result_dict = {'iv': [], 'cipher': [], 'values': []}
        file = open(f"bytes_{z}FFxx.txt", "r")
        while True:
            content = file.readline().rstrip("\n")  # read line and remove extra step
            if not content:
                break
            else:
                iv_c = content.split(' ')
                cipher = iv_c[1]
                iv = iv_c[0]

                k_value = fact3(cipher, m_0, k, iv, d)  # notice this time we pass the list of Ks

                result_dict['iv'].append(iv)
                result_dict['cipher'].append(cipher)
                result_dict['values'].append(k_value)

        df = pd.DataFrame(result_dict)
        values = df['values'].value_counts()
        current_k = values.index[0]  # the most repeated value is the key[i]
        print(f"k[{i}]: {current_k}")
        k.append(current_k)


def get_k1(m0, k0):
    result_dict = {'iv': [], 'cipher': [], 'values': []}
    file = open("bytes_04FFxx.txt", "r")
    while True:
        content = file.readline().rstrip("\n")  # read line and remove extra step
        if not content:
            break
        else:
            iv_c = content.split(' ')

            cipher = iv_c[1]
            iv = iv_c[0]
            fact2_extra = fact2_extra_operation(cipher, m0, k0, iv)

            result_dict['iv'].append(iv)
            result_dict['cipher'].append(cipher)
            result_dict['values'].append(fact2_extra)

    df = pd.DataFrame(result_dict)
    values = df['values'].value_counts()

    return values.index[0]  # the most repeated value


def get_k0(m0):
    result_dict = {'iv': [], 'cipher': [], 'values': []}
    file = open("bytes_03FFxx.txt", "r")
    while True:
        content = file.readline().rstrip("\n")  # read line and remove extra step
        if not content:
            break
        else:
            iv_c = content.split(' ')
            cipher = iv_c[1]
            iv = iv_c[0]
            fact2 = fact2_operation(cipher, m0, iv)

            result_dict['iv'].append(iv)
            result_dict['cipher'].append(cipher)
            result_dict['values'].append(fact2)

    df = pd.DataFrame(result_dict)
    fact2_counts = df['values'].value_counts()

    return fact2_counts.index[0]  # the most repeated value


def get_m0():
    result_dict = {'iv': [], 'cipher': [], 'values': []}
    file = open("bytes_01FFxx.txt", "r")
    while True:
        content = file.readline().rstrip("\n")  # read line and remove extra step
        if not content:
            break
        else:
            iv_c = content.split(' ')

            cipher = iv_c[1]
            iv = iv_c[0]
            fact1 = fact1_byte_operation(cipher, iv)
            #print(f"iv: {iv_c[0]} cipher: {iv_c[1]} Fact1 = {fact1}")
            result_dict['iv'].append(iv)
            result_dict['cipher'].append(cipher)
            result_dict['values'].append(fact1)

    file.close()

    df = pd.DataFrame(result_dict)
    fact1_counts = df['values'].value_counts()

    return fact1_counts.index[0]  # the most repeated value


if __name__ == '__main__':

    k = list()

    m_0 = get_m0()
    print(f"m[0]: {m_0}")

    k_0 = get_k0(m_0)
    print(f"k[0]: {k_0}")
    k.append(k_0)

    k_1 = get_k1(m_0, k_0)
    print(f"k[1]: {k_1}")
    k.append(k_1)

    get_rest_of_k()





