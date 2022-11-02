import os
from tokenize import PlainToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import dh
import hashlib

MSG_TYPES = [b"MSG0", b"MSG1", b"MSG2"]

NONCE_LEN = 16
IV_LEN = 12
MSG_TYPES_LEN = len(MSG_TYPES[0])

MSG_INDEXES = [
    {
        "MSG0": (0,4),
        "RA": (4,4+16)
    },
    {
        "MSG1": (0,4),
        "RB": (4,4+16)
    },
    {
        "MSG2": (0,4),

    },
]

CLNT_STR = b"CLNT"
SRVR_STR = b"SRVR"

CLNT_STR_LEN = len(CLNT_STR)
SRVR_STR_LEN = len(SRVR_STR)

DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
DH_P_LEN = 256

def PopNumBytes(msg, n):
    return msg[:n], msg[n:]

def DecryptAndParse(encrypted_msg, aesgcm, iv, dh_param_nums):
    decrypted_msg = aesgcm.decrypt(iv, encrypted_msg, None)

    request_const, msg = PopNumBytes(decrypted_msg, SRVR_STR_LEN)
    public_key_bytes, nonce = PopNumBytes(msg, DH_P_LEN)

    public_int = int.from_bytes(public_key_bytes, "big")
    public_numbers = dh.DHPublicNumbers(public_int, dh_param_nums)
    public_key_type = public_numbers.public_key()
    
    return request_const, public_key_type, nonce

def PublicKeyToBytes(public_key: dh.DHPublicKey):
    return public_key.public_numbers().y.to_bytes(DH_P_LEN, 'big')

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        # p and g defined by RFC3526
        self._p = DH_P
        self._g = 2
        self._key = None
        self._ra = None
        self._rb = None
        self._iv1 = None
        self._iv2 = None
        self._dha = None
        self._dhb: dh.DHPrivateKey = None
        self._ga_mod_p = None
        self._gb_mod_p: dh.DHPublicKey = None
        self._shared_key = None
        self._aesgcm = None
        self._session_aesgcm = None
        self.auth_finished = False
        # pass

    def InitSharedKey(self, shared_key):
        self._shared_key = shared_key
        self._aesgcm = AESGCM(hashlib.sha256(shared_key.encode()).digest())

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        self._ra = os.urandom(NONCE_LEN) # TODO, investigate size to make this
        
        return b"MSG0"+self._ra


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        return any(message.startswith(TYPE) for TYPE in MSG_TYPES)


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        if (message.startswith(MSG_TYPES[0])):
            msg = message[MSG_TYPES_LEN:]
            self._ra, msg = PopNumBytes(msg, NONCE_LEN)

            parameters = dh.DHParameterNumbers(self._p, self._g).parameters()
            self._dhb = parameters.generate_private_key()
            self._gb_mod_p = self._dhb.public_key()

            self._rb = os.urandom(NONCE_LEN) # TODO, investigate size to make this
            self._iv1 = os.urandom(IV_LEN) # TODO, investigate size to make this
            decrypted_block = b"SRVR" + PublicKeyToBytes(self._gb_mod_p) + self._ra
            
            return b"MSG1" + self._rb + self._iv1 + self._aesgcm.encrypt(self._iv1, decrypted_block, None)


        elif (message.startswith(MSG_TYPES[1])):
            msg = message[MSG_TYPES_LEN:]

            pn = dh.DHParameterNumbers(self._p, self._g)
            parameters = pn.parameters()

            self._rb, msg = PopNumBytes(msg, NONCE_LEN)
            self._iv1, encrypted_msg = PopNumBytes(msg, IV_LEN)

            srvr_const, self._gb_mod_p, ra = DecryptAndParse(encrypted_msg, self._aesgcm, self._iv1, pn)

            if srvr_const != SRVR_STR:
                raise Exception(f'CLIENT (MSG2): srvr_const={srvr_const}, SRVR_STR={SRVR_STR}')

            if ra != self._ra:
                raise Exception(f'CLIENT (MSG2): ra={ra}, self._ra={self._ra}')

            self._iv2 = os.urandom(IV_LEN)
            self._dha = parameters.generate_private_key()
            self._ga_mod_p = self._dha.public_key()

            decrypted_block = b'CLNT' + PublicKeyToBytes(self._ga_mod_p) + self._rb

            self.SetSessionKey(self._dha.exchange(self._gb_mod_p))

            self.auth_finished = True

            return b'MSG2' + self._iv2 + self._aesgcm.encrypt(self._iv2, decrypted_block, None)
            

        elif (message.startswith(MSG_TYPES[2])):
            msg = message[MSG_TYPES_LEN:]
            pn = dh.DHParameterNumbers(self._p, self._g)

            self._iv2, encrypted_msg = PopNumBytes(msg, IV_LEN)
            clnt_const, self._ga_mod_p, rb = DecryptAndParse(encrypted_msg, self._aesgcm, self._iv2, pn)

            
            if clnt_const != CLNT_STR:
                raise Exception(f'SRVR (MSG3): clnt_const{clnt_const}, SLNT_STR={CLNT_STR}')
            
            if rb != self._rb:
                raise Exception(f'SRVR (MSG3): rb={rb}, self._rb={self._rb}')

            self.SetSessionKey(self._dhb.exchange(self._ga_mod_p))

            self.auth_finished = True
            return False


        raise Exception('Invalid Message')


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._session_aesgcm = AESGCM(hashlib.sha256(key).digest())
        self._key = key
        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        iv = os.urandom(12)
        cipher_text = self._session_aesgcm.encrypt(iv, plain_text, None)
        return iv + cipher_text


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        nonce = cipher_text[0:12]
        plain_text = self._session_aesgcm.decrypt(nonce, cipher_text[12:], None)
        return plain_text
        
