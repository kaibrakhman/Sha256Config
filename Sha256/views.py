from django.shortcuts import render
from .forms import *
# Create your views here.

"""This Python module is an implementation of the SHA-256 algorithm.
From https://github.com/keanemind/Python-SHA-256"""

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def generate_hash(message: bytearray) -> bytearray:
    """Return a SHA-256 hash from the message passed.
    The argument should be a bytes, bytearray, or
    string object."""
    if isinstance(message, str):
        message = bytearray(message, 'ascii')
    elif isinstance(message, bytes):
        message = bytearray(message)
    elif not isinstance(message, bytearray):
        raise TypeError

    # Padding
    length = len(message) * 8 # len(message) is number of BYTES!!!
    message.append(0x80)
    while (len(message) * 8 + 64) % 512 != 0:
        message.append(0x00)

    message += length.to_bytes(8, 'big') # pad to 8 bytes or 64 bits

    assert (len(message) * 8) % 512 == 0, "Padding did not complete properly!"

    # Parsing
    blocks = [] # contains 512-bit chunks of message
    for i in range(0, len(message), 64): # 64 bytes is 512 bits
        blocks.append(message[i:i+64])

    # Setting Initial Hash Value
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h5 = 0x9b05688c
    h4 = 0x510e527f
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    # SHA-256 Hash Computation
    for message_block in blocks:
        # Prepare message schedule
        message_schedule = []
        for t in range(0, 64):
            if t <= 15:
                # adds the t'th 32 bit word of the block,
                # starting from leftmost word
                # 4 bytes at a time
                message_schedule.append(bytes(message_block[t*4:(t*4)+4]))
            else:
                term1 = _sigma1(int.from_bytes(message_schedule[t-2], 'big'))
                term2 = int.from_bytes(message_schedule[t-7], 'big')
                term3 = _sigma0(int.from_bytes(message_schedule[t-15], 'big'))
                term4 = int.from_bytes(message_schedule[t-16], 'big')

                # append a 4-byte byte object
                schedule = ((term1 + term2 + term3 + term4) % 2**32).to_bytes(4, 'big')
                message_schedule.append(schedule)

        assert len(message_schedule) == 64

        # Initialize working variables
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # Iterate for t=0 to 63
        for t in range(64):
            t1 = ((h + _capsigma1(e) + _ch(e, f, g) + K[t] +
                   int.from_bytes(message_schedule[t], 'big')) % 2**32)

            t2 = (_capsigma0(a) + _maj(a, b, c)) % 2**32

            h = g
            g = f
            f = e
            e = (d + t1) % 2**32
            d = c
            c = b
            b = a
            a = (t1 + t2) % 2**32

        # Compute intermediate hash value
        h0 = (h0 + a) % 2**32
        h1 = (h1 + b) % 2**32
        h2 = (h2 + c) % 2**32
        h3 = (h3 + d) % 2**32
        h4 = (h4 + e) % 2**32
        h5 = (h5 + f) % 2**32
        h6 = (h6 + g) % 2**32
        h7 = (h7 + h) % 2**32

    return ((h0).to_bytes(4, 'big') + (h1).to_bytes(4, 'big') +
            (h2).to_bytes(4, 'big') + (h3).to_bytes(4, 'big') +
            (h4).to_bytes(4, 'big') + (h5).to_bytes(4, 'big') +
            (h6).to_bytes(4, 'big') + (h7).to_bytes(4, 'big'))

def _sigma0(num: int):
    """As defined in the specification."""
    num = (_rotate_right(num, 7) ^
           _rotate_right(num, 18) ^
           (num >> 3))
    return num

def _sigma1(num: int):
    """As defined in the specification."""
    num = (_rotate_right(num, 17) ^
           _rotate_right(num, 19) ^
           (num >> 10))
    return num

def _capsigma0(num: int):
    """As defined in the specification."""
    num = (_rotate_right(num, 2) ^
           _rotate_right(num, 13) ^
           _rotate_right(num, 22))
    return num

def _capsigma1(num: int):
    """As defined in the specification."""
    num = (_rotate_right(num, 6) ^
           _rotate_right(num, 11) ^
           _rotate_right(num, 25))
    return num

def _ch(x: int, y: int, z: int):
    """As defined in the specification."""
    return (x & y) ^ (~x & z)

def _maj(x: int, y: int, z: int):
    """As defined in the specification."""
    return (x & y) ^ (x & z) ^ (y & z)

def _rotate_right(num: int, shift: int, size: int = 32):
    """Rotate an integer right."""
    return (num >> shift) | (num << size - shift)


def index(request):
    output = ""
    if request.method == "POST":
        form = ContactForm(request.POST)
        inputtxt = request.POST['text']
        output = generate_hash(inputtxt).hex()
    else:
        form = ContactForm()

    return render(request,"index.html", {'form': form,'output': output})






import math


F = lambda x, y, z: ((x & y) | ((~x) & z))
G = lambda x, y, z: ((x & z) | (y & (~z)))
H = lambda x, y, z: (x ^ y ^ z)
I = lambda x, y, z: (y ^ (x | (~z)))
L = lambda x, n: (((x << n) | (x >> (32 - n))) & (0xffffffff))
shi_1 = (7, 12, 17, 22) * 4
shi_2 = (5, 9, 14, 20) * 4
shi_3 = (4, 11, 16, 23) * 4
shi_4 = (6, 10, 15, 21) * 4
m_1 = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
m_2 = (1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12)
m_3 = (5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2)
m_4 = (0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9)


def T(i):
    return (int(4294967296 * abs(math.sin(i)))) & 0xffffffff


def shift(shift_list):
    shift_list = [shift_list[3], shift_list[0], shift_list[1], shift_list[2]]
    return shift_list


def fun(fun_list, f, m, shi):
    count = 0
    global Ti_count
    while count < 16:
        xx = int(fun_list[0], 16) + f(int(fun_list[1], 16), int(fun_list[2], 16), int(fun_list[3], 16)) + int(m[count], 16) + T(Ti_count)
        xx &= 0xffffffff
        ll = L(xx, shi[count])
        fun_list[0] = hex((int(fun_list[1], 16) + ll) & 0xffffffff)
        fun_list = shift(fun_list)
        count += 1
        Ti_count += 1
    return fun_list


def gen_m16(order, ascii_list, f_offset):
    ii = 0
    m16 = [0] * 16
    f_offset *= 64
    for i in order:
        i *= 4
        m16[ii] = '0x' + ''.join((ascii_list[i + f_offset] + ascii_list[i + 1 + f_offset] + ascii_list[i + 2 + f_offset] + ascii_list[i + 3 + f_offset]).split('0x'))
        ii += 1
    for ind in range(len(m16)):
        m16[ind] = reverse_hex(m16[ind])
    return m16


def reverse_hex(hex_str):
    hex_str = hex_str[2:]
    if len(hex_str) < 8:
        hex_str = '0' * (8 - len(hex_str)) + hex_str
    hex_str_list = []
    for i in range(0, len(hex_str), 2):
        hex_str_list.append(hex_str[i:i + 2])
    hex_str_list.reverse()
    hex_str_result = '0x' + ''.join(hex_str_list)
    return hex_str_result


def show_result(f_list):
    result = ''
    f_list1 = [0] * 4
    for i in f_list:
        f_list1[f_list.index(i)] = reverse_hex(i)[2:]
        result += f_list1[f_list.index(i)]
    return result


def padding(input_m, msg_lenth=0):
    ascii_list = list(map(hex, map(ord, input_m)))
    msg_lenth += len(ascii_list) * 8
    ascii_list.append('0x80')
    for i in range(len(ascii_list)):
        if len(ascii_list[i]) < 4:
            ascii_list[i] = '0x' + '0' + ascii_list[i][2:]
    while (len(ascii_list) * 8 + 64) % 512 != 0:
        ascii_list.append('0x00')
    msg_lenth_0x = hex(msg_lenth)[2:]
    msg_lenth_0x = '0x' + msg_lenth_0x.rjust(16, '0')
    msg_lenth_0x_big_order = reverse_hex(msg_lenth_0x)[2:]
    msg_lenth_0x_list = []
    for i in range(0, len(msg_lenth_0x_big_order), 2):
        msg_lenth_0x_list.append('0x' + msg_lenth_0x_big_order[i: i + 2])
    ascii_list.extend(msg_lenth_0x_list)
    return ascii_list


def md5(input_m):
    global Ti_count
    Ti_count = 1
    abcd_list = ['0x67452301', '0xefcdab89', '0x98badcfe', '0x10325476']
    ascii_list = padding(input_m)
    for i in range(0, len(ascii_list) // 64):
        aa, bb, cc, dd = abcd_list
        order_1 = gen_m16(m_1, ascii_list, i)
        order_2 = gen_m16(m_2, ascii_list, i)
        order_3 = gen_m16(m_3, ascii_list, i)
        order_4 = gen_m16(m_4, ascii_list, i)
        abcd_list = fun(abcd_list, F, order_1, shi_1)
        abcd_list = fun(abcd_list, G, order_2, shi_2)
        abcd_list = fun(abcd_list, H, order_3, shi_3)
        abcd_list = fun(abcd_list, I, order_4, shi_4)
        output_a = hex((int(abcd_list[0], 16) + int(aa, 16)) & 0xffffffff)
        output_b = hex((int(abcd_list[1], 16) + int(bb, 16)) & 0xffffffff)
        output_c = hex((int(abcd_list[2], 16) + int(cc, 16)) & 0xffffffff)
        output_d = hex((int(abcd_list[3], 16) + int(dd, 16)) & 0xffffffff)
        abcd_list = [output_a, output_b, output_c, output_d]
        Ti_count = 1
    return show_result(abcd_list)


# md5-Length Extension Attack: 计算 md5(message + padding + suffix), res = md5(message), len_m = len(message)
def md5_lea(suffix, res, len_m):
    global Ti_count
    Ti_count = 1
    abcd_list = []
    for i in range(0, 32, 8):
        abcd_list.append(reverse_hex('0x' + res[i: i + 8]))
    ascii_list = padding(suffix, (len_m + 72) // 64 * 64 * 8)  # len(message + padding) * 8
    for i in range(0, len(ascii_list) // 64):
        aa, bb, cc, dd = abcd_list
        order_1 = gen_m16(m_1, ascii_list, i)
        order_2 = gen_m16(m_2, ascii_list, i)
        order_3 = gen_m16(m_3, ascii_list, i)
        order_4 = gen_m16(m_4, ascii_list, i)
        abcd_list = fun(abcd_list, F, order_1, shi_1)
        abcd_list = fun(abcd_list, G, order_2, shi_2)
        abcd_list = fun(abcd_list, H, order_3, shi_3)
        abcd_list = fun(abcd_list, I, order_4, shi_4)
        output_a = hex((int(abcd_list[0], 16) + int(aa, 16)) & 0xffffffff)
        output_b = hex((int(abcd_list[1], 16) + int(bb, 16)) & 0xffffffff)
        output_c = hex((int(abcd_list[2], 16) + int(cc, 16)) & 0xffffffff)
        output_d = hex((int(abcd_list[3], 16) + int(dd, 16)) & 0xffffffff)
        abcd_list = [output_a, output_b, output_c, output_d]
        Ti_count = 1
    return show_result(abcd_list)

# print(s)
# print(md5_lea('a', s, 3))
def md55(request):
    output = ""
    if request.method == "POST":
        form = ContactForm(request.POST)
        inputtxt = request.POST['text']
        output = md5(inputtxt)
    else:
        form = ContactForm()

    return render(request, "md5.html", {'form': form, 'output': output})



__author__ = ('Leonardo F Oliveira')

__all__ = ['encode', 'decode']


class b64:

    def __init__(self):
        self.table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    def __str__(self):
        return 'Base64 Encoder / Decoder'

    def encode(self, text):
        bins = str()
        for c in text:
            bins += '{:0>8}'.format(str(bin(ord(c)))[2:])
        while len(bins) % 3:
            bins += '00000000'
        d = 1
        for i in range(6, len(bins) + int(len(bins) / 6), 7):
            bins = bins[:i] + ' ' + bins[i:]
        bins = bins.split(' ')
        if '' in bins:
            bins.remove('')
        base64 = str()
        for b in bins:
            if b == '000000':
                base64 += '='
            else:
                base64 += self.table[int(b, 2)]
        return base64

    def decode(self, text):
        bins = str()
        for c in text:
            if c == '=':
                bins += '000000'
            else:
                bins += '{:0>6}'.format(str(bin(self.table.index(c)))[2:])
        for i in range(8, len(bins) + int(len(bins) / 8), 9):
            bins = bins[:i] + ' ' + bins[i:]
        bins = bins.split(' ')
        if '' in bins:
            bins.remove('')
        text = str()
        for b in bins:
            if not b == '00000000':
                text += chr(int(b, 2))
        return text

    def test(self):
        e = 'Running Class Test'
        d = 'UnVubmluZyBDbGFzcyBUZXN0'
        if e == decode(d) and d == encode(e):
            return True
        else:
            return False


_inst = b64()
encode = _inst.encode
decode = _inst.decode


print(encode("dad"))



def base644(request):
    output = ""
    if request.method == "POST":
        form = ContactForm(request.POST)
        inputtxt = request.POST['text']
        output = encode(inputtxt)
    else:
        form = ContactForm()

    return render(request,"base64.html", {'form': form,'output': output})

def base644decode(request):
    output = ""
    if request.method == "POST":
        form = ContactForm(request.POST)
        inputtxt = request.POST['text']
        output = decode(inputtxt)
    else:
        form = ContactForm()

    return render(request,"base64decode.html", {'form': form,'output': output})


