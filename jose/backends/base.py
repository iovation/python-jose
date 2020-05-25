from ..utils import base64url_encode


class Key(object):
    """
    A simple interface for implementing JWK keys.
    """
    def __init__(self, key, algorithm):
        pass

    def sign(self, msg):
        raise NotImplementedError()

    def verify(self, msg, sig):
        raise NotImplementedError()

    def public_key(self):
        raise NotImplementedError()

    def to_pem(self):
        raise NotImplementedError()

    def to_dict(self):
        raise NotImplementedError()

    def encrypt(self, plain_text, aad=None):
        """
        Encrypt the plain text and generate an auth tag if appropriate

        Args:
            plain_text (bytes): Data to encrypt
            aad (bytes, optional): Authenticated Additional Data if key's algorithm supports auth mode

        Returns:
            (bytes, bytes, bytes): IV, cipher text, and auth tag
        """
        raise NotImplementedError()

    def decrypt(self, cipher_text, iv=None, aad=None, tag=None):
        """
        :param cipher_text: Cipher text to decrypt
        :type cipher_text: bytes
        :param iv: IV if block mode
        :type iv: bytes
        :param aad: Additional Authenticated Data to verify if auth mode
        :type aad: bytes
        :param tag: Authentication tag if auth mode
        :type tag: bytes
        :return: Decrypted value
        :rtype: bytes
        """
        raise NotImplementedError()


class DIRKey(Key):
    def __init__(self, key_data, algorithm):
        self._key = key_data
        self._alg = algorithm

    def to_dict(self):
        return {
            'alg': self._alg,
            'kty': 'oct',
            'k': base64url_encode(self._key),
        }
