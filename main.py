import pandas as pd
import numpy as np


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


if __name__ == '__main__':
    result_dict = {'iv': [],'cipher': [], 'fact1': []}
    file = open("iv_ciphers.txt", "r")
    k = list()
    while True:
        content = file.readline().rstrip("\n") #read line and remove extra step
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
            result_dict['fact1'].append(fact1)

    file.close()

    df = pd.DataFrame(result_dict)
    fact1_counts = df['fact1'].value_counts()
    fact1_most_repeated = fact1_counts.index[0]
    print(f"most repeated value in fact1: {fact1_most_repeated}")

    df["fact2"] = ""
    for index, row in df.iterrows():
        fact2 = fact2_operation(row["cipher"], fact1_most_repeated, row["iv"])
        df.at[index, 'fact2'] = fact2

    fact2_counts = df['fact2'].value_counts()
    k0 = fact2_counts.index[0]
    print(f"most repeated value in fact2: {k0}")
    k.append(k0)

    df["fact2_extra"] = ""
    for index, row in df.iterrows():
        fact2_extra = fact2_extra_operation(row["cipher"], fact1_most_repeated, k0, row["iv"])
        df.at[index, 'fact2_extra'] = fact2_extra

    print(df.head())
    """
    #for testing:
    cipher = "0xFF"
    iv = "0X01FF00"
    byte_operation(cipher, iv)"""
