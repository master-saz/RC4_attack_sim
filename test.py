import main as mn
import pandas as pd

if __name__ == '__main__':
    file = open("copy.txt", "r")
    new_lines = list()
    while True:
        content = file.readline().rstrip("\n")  # read line and remove extra step
        if not content:
            break
        else:
            line = content.split(' ')
            for cipher in line:
                new_lines.append(cipher)
    file.close()

    myfile = open('new_bytes_01FFxx.txt', 'w')
    count = 0
    for line in new_lines:
        new_line = f"01FF{'0x{0:02x}'.format(count).upper()} {line[0:2]}"
        myfile.write("%s\n" % new_line)
        count +=1

    myfile.close()

    m_0 = mn.get_m0('new_bytes_01FFxx.txt')
    print(f"m[0]: {m_0}")

    file = open("copy3.txt", "r")
    new_lines = list()
    while True:
        content = file.readline().rstrip("\n")  # read line and remove extra step
        if not content:
            break
        else:
            line = content.split(' ')
            for cipher in line:
                new_lines.append(cipher)
    file.close()

    myfile = open('new_bytes_03FFxx.txt', 'w')
    count = 0
    for line in new_lines:
        new_line = f"03FF{'0x{0:02x}'.format(count).upper()} {line[0:2]}"
        myfile.write("%s\n" % new_line)
        count += 1

    myfile.close()

    k_0 = mn.get_k0(m_0, "new_bytes_03FFxx.txt")
    print(f"k[0]: {k_0}")