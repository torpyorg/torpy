# Copyright 2019 James Brown
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import hmac
import logging

from torpy.crypto_common import *
from torpy.crypto import kdf_tor
from torpy.utils import to_hex

logger = logging.getLogger(__name__)


class NtorError(Exception):
    pass


class TapError(Exception):
    pass


class TapKeyAgreement:
    #
    # 5.1.3. The "TAP" handshake
    #
    # This handshake uses Diffie-Hellman in Z_p and RSA to compute a set of
    # shared keys which the client knows are shared only with a particular
    # server, and the server knows are shared with whomever sent the
    # original handshake (or with nobody at all).  It's not very fast and
    # not very good.  (See Goldberg's "On the Security of the Tor
    # Authentication Protocol".)
    #
    # Define TAP_C_HANDSHAKE_LEN as DH_LEN+KEY_LEN+PK_PAD_LEN.
    # Define TAP_S_HANDSHAKE_LEN as DH_LEN+HASH_LEN.
    #
    # The payload for a CREATE cell is an 'onion skin', which consists of
    # the first step of the DH handshake data (also known as g^x).  This
    # value is hybrid-encrypted (see 0.3) to the server's onion key, giving
    # a client handshake of:
    #
    #     PK-encrypted:
    #       Padding                       [PK_PAD_LEN bytes]
    #       Symmetric key                 [KEY_LEN bytes]
    #       First part of g^x             [PK_ENC_LEN-PK_PAD_LEN-KEY_LEN bytes]
    #     Symmetrically encrypted:
    #       Second part of g^x            [DH_LEN-(PK_ENC_LEN-PK_PAD_LEN-KEY_LEN)
    #                                         bytes]
    #
    # The payload for a CREATED cell, or the relay payload for an
    # EXTENDED cell, contains:
    #       DH data (g^y)                 [DH_LEN bytes]
    #       Derivative key data (KH)      [HASH_LEN bytes]   <see 5.2 below>
    #
    # Once the handshake between the OP and an OR is completed, both can
    # now calculate g^xy with ordinary DH.  Before computing g^xy, both parties
    # MUST verify that the received g^x or g^y value is not degenerate;
    # that is, it must be strictly greater than 1 and strictly less than p-1
    # where p is the DH modulus.  Implementations MUST NOT complete a handshake
    # with degenerate keys.  Implementations MUST NOT discard other "weak"
    # g^x values.
    #
    # (Discarding degenerate keys is critical for security; if bad keys
    # are not discarded, an attacker can substitute the OR's CREATED
    # cell's g^y with 0 or 1, thus creating a known g^xy and impersonating
    # the OR. Discarding other keys may allow attacks to learn bits of
    # the private key.)
    #
    # Once both parties have g^xy, they derive their shared circuit keys
    # and 'derivative key data' value via the KDF-TOR function in 5.2.1.
    #
    def __init__(self, onion_router):
        self._private_key = dh_private()
        self._public_key = dh_public(self._private_key)

    @property
    def public_key_bytes(self):
        return dh_public_to_bytes(self._public_key)

    def complete_handshake(self, handshake_data):
        peer_pub_key_bytes = handshake_data[:128]
        auth = handshake_data[128:]  # tap auth is SHA1, 20 in bytes?
        assert len(auth) == 20, 'recieved wrong sha1 len'

        peer_pub_key = df_public_from_bytes(peer_pub_key_bytes)
        shared_secret = dh_shared(self._private_key, peer_pub_key)
        computed_auth, key_material = kdf_tor(shared_secret)
        if computed_auth != auth:
            raise TapError('auth input does not match.')

        # Cut unused bytes
        return key_material[:72]


class NtorKeyAgreement:
    def __init__(self, onion_router):
        # 5.1.4. The "ntor" handshake

        # This handshake uses a set of DH handshakes to compute a set of
        # shared keys which the client knows are shared only with a particular
        # server, and the server knows are shared with whomever sent the
        # original handshake (or with nobody at all).  Here we use the
        # "curve25519" group and representation as specified in "Curve25519:
        # new Diffie-Hellman speed records" by D. J. Bernstein.

        # [The ntor handshake was added in Tor 0.2.4.8-alpha.]

        # In this section, define:
        #   H(x,t) as HMAC_SHA256 with message x and key t.
        #   H_LENGTH  = 32.
        #   ID_LENGTH = 20.
        #   G_LENGTH  = 32
        #   PROTOID   = "ntor-curve25519-sha256-1"
        #   t_mac     = PROTOID | ":mac"
        #   t_key     = PROTOID | ":key_extract"
        #   t_verify  = PROTOID | ":verify"
        #   MULT(a,b) = the multiplication of the curve25519 point 'a' by the
        #               scalar 'b'.
        #   G         = The preferred base point for curve25519 ([9])
        #   KEYGEN()  = The curve25519 key generation algorithm, returning
        #               a private/public keypair.
        #   m_expand  = PROTOID | ":key_expand"

        # H is defined as hmac()
        # MULT is included in the curve25519 library as get_shared_key()
        # KEYGEN() is curve25519.Private()
        self.protoid = b'ntor-curve25519-sha256-1'
        self.t_mac = self.protoid + b':mac'
        self.t_key = self.protoid + b':key_extract'
        self.t_verify = self.protoid + b':verify'
        self.m_expand = self.protoid + b':key_expand'

        #logger.debug("identity_fingerprint: " + to_hex(onion_router.fingerprint))

        # To perform the handshake, the client needs to know an identity key
        # digest for the server, and an ntor onion key (a curve25519 public
        # key) for that server. Call the ntor onion key "B".  The client
        # generates a temporary keypair:
        #     x,X = KEYGEN()
        self._x = curve25519_private()
        #logger.debug("ntor private key: " + to_hex(curve25519_to_bytes(self._x)))

        self._X = curve25519_public_from_private(self._x)
        #logger.debug("ntor public key: " + to_hex(curve25519_to_bytes(self._X)))

        self._fingerprint_bytes = onion_router.fingerprint

        self._B = curve25519_public_from_bytes(onion_router.descriptor.ntor_key)

        # and generates a client-side handshake with contents:
        #   NODEID      Server identity digest  [ID_LENGTH bytes]
        #   KEYID       KEYID(B)                [H_LENGTH bytes]
        #   CLIENT_PK   X                       [G_LENGTH bytes]
        self._handshake = self._fingerprint_bytes
        self._handshake += curve25519_to_bytes(self._B)
        self._handshake += curve25519_to_bytes(self._X)

    @property
    def handshake(self):
        return self._handshake

    def complete_handshake(self, handshake_data):
        # The server's handshake reply is:
        # SERVER_PK   Y                       [G_LENGTH bytes]
        # AUTH        H(auth_input, t_mac)    [H_LENGTH bytes]
        Y = handshake_data[:32]     # ntor data curve25519::public_key::key_size_in_bytes
        auth = handshake_data[32:]  # ntor auth is SHA1, 32 in bytes?
        assert len(auth) == 32      #

        # The client then checks Y is in G^* [see NOTE below], and computes

        # secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID

        si  = curve25519_get_shared(self._x, curve25519_public_from_bytes(Y))
        si += curve25519_get_shared(self._x, self._B)
        si += self._fingerprint_bytes
        si += curve25519_to_bytes(self._B)
        si += curve25519_to_bytes(self._X)
        si += Y
        si += b'ntor-curve25519-sha256-1'

        # KEY_SEED = H(secret_input, t_key)
        # verify = H(secret_input, t_verify)
        key_seed = hmac(self.t_key, si)
        verify = hmac(self.t_verify, si)

        # auth_input = verify | ID | B | Y | X | PROTOID | "Server"
        ai = verify
        ai += self._fingerprint_bytes
        ai += curve25519_to_bytes(self._B)
        ai += Y
        ai += curve25519_to_bytes(self._X)
        ai += self.protoid
        ai += b'Server'

        # The client verifies that AUTH == H(auth_input, t_mac).
        if auth != hmac(self.t_mac, ai):
            raise NtorError('auth input does not match.')

        # Both parties check that none of the EXP() operations produced the
        # point at infinity. [NOTE: This is an adequate replacement for
        # checking Y for group membership, if the group is curve25519.]

        # Both parties now have a shared value for KEY_SEED.  They expand this
        # into the keys needed for the Tor relay protocol, using the KDF
        # described in 5.2.2 and the tag m_expand.

        # 5.2.2. KDF-RFC5869

        # For newer KDF needs, Tor uses the key derivation function HKDF from
        # RFC5869, instantiated with SHA256.  (This is due to a construction
        # from Krawczyk.)  The generated key material is:

        #     K = K_1 | K_2 | K_3 | ...

        #     Where H(x,t) is HMAC_SHA256 with value x and key t
        #       and K_1     = H(m_expand | INT8(1) , KEY_SEED )
        #       and K_(i+1) = H(K_i | m_expand | INT8(i+1) , KEY_SEED )
        #       and m_expand is an arbitrarily chosen value,
        #       and INT8(i) is a octet with the value "i".

        # In RFC5869's vocabulary, this is HKDF-SHA256 with info == m_expand,
        # salt == t_key, and IKM == secret_input.
        # WARN: length must be 92
        # 72 + byte_type rend_nonce     [20]; << ignored now
        return hkdf_sha256(key_seed, length=72, info=self.m_expand)
