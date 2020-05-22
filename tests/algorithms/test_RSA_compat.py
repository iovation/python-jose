import pytest

try:
    from jose.backends.rsa_backend import RSAKey as PurePythonRSAKey
    from jose.backends.cryptography_backend import CryptographyRSAKey
    from jose.backends.pycrypto_backend import RSAKey as PyCryptoRSAKey
except ImportError:
    PurePythonRSAKey = CryptographyRSAKey = PyCryptoRSAKey = None
from jose.constants import ALGORITHMS
from jose.exceptions import JWEError

from .test_RSA import PRIVATE_KEYS

CRYPTO_BACKENDS = (
    pytest.param(PurePythonRSAKey, id="python_rsa"),
    pytest.param(CryptographyRSAKey, id="pyca/cryptography"),
    pytest.param(PyCryptoRSAKey, id="pycrypto/dome")
)
ENCODINGS = ("PKCS1", "PKCS8")


@pytest.mark.backend_compatibility
@pytest.mark.skipif(
    None in (PurePythonRSAKey, CryptographyRSAKey, PyCryptoRSAKey),
    reason="Multiple crypto backends not available for backend compatibility tests"
)
class TestBackendRsaCompatibility(object):

    @pytest.mark.parametrize("BackendSign", CRYPTO_BACKENDS)
    @pytest.mark.parametrize("BackendVerify", CRYPTO_BACKENDS)
    @pytest.mark.parametrize("private_key", PRIVATE_KEYS)
    def test_signing_parity(self, BackendSign, BackendVerify, private_key):
        key_sign = BackendSign(private_key, ALGORITHMS.RS256)
        key_verify = BackendVerify(private_key, ALGORITHMS.RS256).public_key()

        msg = b'test'
        sig = key_sign.sign(msg)

        # valid signature
        assert key_verify.verify(msg, sig)

        # invalid signature
        assert not key_verify.verify(msg, b'n' * 64)

    @pytest.mark.parametrize("encoding", ENCODINGS)
    @pytest.mark.parametrize("BackendFrom", CRYPTO_BACKENDS)
    @pytest.mark.parametrize("BackendTo", CRYPTO_BACKENDS)
    @pytest.mark.parametrize("private_key", PRIVATE_KEYS)
    def test_public_key_to_pem(self, BackendFrom, BackendTo, encoding, private_key):
        key = BackendFrom(private_key, ALGORITHMS.RS256)
        key2 = BackendTo(private_key, ALGORITHMS.RS256)

        key1_pem = key.public_key().to_pem(pem_format=encoding).strip()
        key2_pem = key2.public_key().to_pem(pem_format=encoding).strip()
        assert key1_pem == key2_pem

    @pytest.mark.parametrize("encoding", ENCODINGS)
    @pytest.mark.parametrize("BackendFrom", CRYPTO_BACKENDS)
    @pytest.mark.parametrize("BackendTo", CRYPTO_BACKENDS)
    @pytest.mark.parametrize("private_key", PRIVATE_KEYS)
    def test_private_key_to_pem(self, BackendFrom, BackendTo, encoding, private_key):
        key = BackendFrom(private_key, ALGORITHMS.RS256)
        key2 = BackendTo(private_key, ALGORITHMS.RS256)

        key1_pem = key.to_pem(pem_format=encoding).strip()
        key2_pem = key2.to_pem(pem_format=encoding).strip()

        import base64
        a = base64.b64decode(key1_pem[key1_pem.index(b"\n"):key1_pem.rindex(b"\n")])
        b = base64.b64decode(key2_pem[key2_pem.index(b"\n"):key2_pem.rindex(b"\n")])
        assert a == b

        assert key1_pem == key2_pem

    @pytest.mark.parametrize("encoding_save", ENCODINGS)
    @pytest.mark.parametrize("encoding_load", ENCODINGS)
    @pytest.mark.parametrize("BackendFrom", CRYPTO_BACKENDS)
    @pytest.mark.parametrize("BackendTo", CRYPTO_BACKENDS)
    @pytest.mark.parametrize("private_key", PRIVATE_KEYS)
    def test_public_key_load_cycle(self, BackendFrom, BackendTo, encoding_save, encoding_load, private_key):
        key = BackendFrom(private_key, ALGORITHMS.RS256)

        pem_pub_reference = key.public_key().to_pem(pem_format=encoding_save).strip()
        pem_pub_load = key.public_key().to_pem(pem_format=encoding_load).strip()

        pubkey_2 = BackendTo(pem_pub_load, ALGORITHMS.RS256)

        assert pem_pub_reference == pubkey_2.to_pem(encoding_save).strip()

    @pytest.mark.parametrize("encoding_save", ENCODINGS)
    @pytest.mark.parametrize("encoding_load", ENCODINGS)
    @pytest.mark.parametrize("BackendFrom", CRYPTO_BACKENDS)
    @pytest.mark.parametrize("BackendTo", CRYPTO_BACKENDS)
    @pytest.mark.parametrize("private_key", PRIVATE_KEYS)
    def test_private_key_load_cycle(self, BackendFrom, BackendTo, encoding_save, encoding_load, private_key):
        key = BackendFrom(private_key, ALGORITHMS.RS256)

        pem_reference = key.to_pem(pem_format=encoding_save).strip()
        pem_load = key.to_pem(pem_format=encoding_load).strip()

        key_2 = BackendTo(pem_load, ALGORITHMS.RS256)

        assert pem_reference == key_2.to_pem(encoding_save).strip()

    @pytest.mark.parametrize("backend_encrypt", CRYPTO_BACKENDS)
    @pytest.mark.parametrize("backend_decrypt", CRYPTO_BACKENDS)
    @pytest.mark.parametrize("algorithm", filter(lambda x: x in ALGORITHMS.SUPPORTED, ALGORITHMS.RSA_KW))
    @pytest.mark.parametrize("private_key", PRIVATE_KEYS)
    def test_encryption_parity(self, backend_encrypt, backend_decrypt, private_key, algorithm):
        if algorithm in (ALGORITHMS.RSA_OAEP, ALGORITHMS.RSA_OAEP_256) \
                and PurePythonRSAKey in (backend_encrypt, backend_decrypt):
            pytest.skip("Pure RSA does not support OAEP")
        key_encrypt = backend_encrypt(private_key, algorithm).public_key()
        key_decrypt = backend_decrypt(private_key, algorithm)

        plain_text = b'test'
        _, cipher_text, _ = key_encrypt.encrypt(plain_text)

        # verify decrypt to original plain text
        actual = key_decrypt.decrypt(cipher_text)
        assert actual == plain_text

        with pytest.raises(JWEError):
            key_decrypt.decrypt(b'n' * 64)
