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
        :param plain_text: Data to encrypt
        :type plain_text: bytes
        :param aad: Authenticated Additional Data if auth mode
        :type aad: bytes
        :return: IV if block mode, cipher text, and auth tag if mode supports
        :rtype: tuple[bytes, bytes, bytes]
        """
        raise NotImplementedError()

    def decrypt(self, cipher_text, iv=None, aad=None, tag=None):
        """
        :param cipher_text: Cipher text to decrypt
        :type cipher_text: bytes
        :param iv: IV if block mode
        :type iv: bytes
        :param aad: Authenticated Additional Data to verify if auth mode
        :type aad: bytes
        :param tag: Authentication tag if auth mode
        :type tag: bytes
        :return: Decrypted value
        :rtype: bytes
        """
        raise NotImplementedError()
