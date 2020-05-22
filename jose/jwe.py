import binascii
import json

import six

try:
    from collections.abc import Mapping  # Python 3
except ImportError:
    from collections import Mapping  # Python 2, will be deprecated in Python 3.8

from .constants import ALGORITHMS
from .exceptions import JWEParseError
from .utils import base64url_decode


def encrypt(plaintext, key, encryption=ALGORITHMS.A256GCM,
            algorithm=ALGORITHMS.DIR, zip=None, content_type=None):
    """Encrypts plaintext and returns a JWE cmpact serialization string.

    Args:
        plaintext (bytes): A bytes object to encrypt
        key (str or dict): The key(s) to use for encrypting the content. Can be
            individual JWK or JWK set.
        encryption (str, optional): The content encryption algorithm used to
            perform authenticated encryption on the plaintext to produce the
            ciphertext and the Authentication Tag.  Defaults to A256GCM.
        algorithm (str, optional): The cryptographic algorithm used
            to encrypt or determine the value of the CEK.  Defaults to dir.
        zip (bool, optional): The compression algorithm) applied to the
            plaintext before encryption. Defaults to None.
        content_type (str, optional): The media type for the secured content.
            See http://www.iana.org/assignments/media-types/media-types.xhtml



    Returns:
        str: The string representation of the header, encrypted key,
            initialization vector, ciphertext, and authentication tag.

    Raises:
        JWSError: If there is an error signing the token.

    Examples:
        >>> from jose import jwe
        >>> jwe.encrypt(b'Hello, World!', 'secret')
        'eyJhbGciOiJIUzI1NiIsInR5cCI.6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QG.s52AzC8Ru8'

    """
    # todo: Update examples with real values
    pass


def decrypt(jwe_str, key):
    """Decrypts a JWE compact serialized string and returns the plaintext.

    Args:
        jwe_str (str): A JWE to be decrypt.
        key (str or dict): A key to attempt to decrypt the payload with. Can be
            individual JWK or JWK set.

    Returns:
        bytes: The plaintext bytes, assuming the authentication tag is valid.

    Raises:
        JWEError: If there is an exception verifying the token.

    Examples:
        >>> from jose import jwe
        >>> jwe_string = 'eyJhbGciOiJIUzI1N.6IkpXVCJ9.eyJhIjoiYiJ9.QgmxZ5yq8z0lXS67_QG.s52AzC8Ru8'
        >>> jwe.decrypt(jwe_string, 'secret')
        b'Hello, World!'
    """
    # todo: Update examples with real values
    header, encrypted_key, iv, ciphertext, auth_tag = _load(jwe_str)


def get_unverified_header(jwe_str):
    """Returns the decoded headers without verification of any kind.

    Args:
        jwe_str (str): A compact serialized JWE to decode the headers from.

    Returns:
        dict: The dict representation of the JWE headers.

    Raises:
        JWEError: If there is an exception decoding the JWE.
    """
    header = _load(jwe_str)[0]
    return header


def _load(jwe_str):
    if isinstance(jwe_str, six.text_type):
        jwe_str = jwe_str.encode('utf-8')
    try:
        header_segment, encrypted_key_segment, iv_segment, ciphertext_segment, auth_tag_segment = jwe_str.split(
            b'.', 4)
        header_data = base64url_decode(header_segment)
    except ValueError:
        raise JWEParseError('Not enough segments')
    except (TypeError, binascii.Error):
        raise JWEParseError('Invalid header')

    try:
        header = json.loads(header_data.decode('utf-8'))
    except ValueError as e:
        raise JWEParseError('Invalid header string: %s' % e)

    if not isinstance(header, Mapping):
        raise JWEParseError('Invalid header string: must be a json object')

    try:
        encrypted_key = base64url_decode(encrypted_key_segment)
    except (TypeError, binascii.Error):
        raise JWEParseError('Invalid encrypted key')

    try:
        iv = base64url_decode(iv_segment)
    except (TypeError, binascii.Error):
        raise JWEParseError('Invalid IV')

    try:
        ciphertext = base64url_decode(ciphertext_segment)
    except (TypeError, binascii.Error):
        raise JWEParseError('Invalid cyphertext')

    try:
        auth_tag = base64url_decode(auth_tag_segment)
    except (TypeError, binascii.Error):
        raise JWEParseError('Invalid auth tag')

    return header, encrypted_key, iv, ciphertext, auth_tag
