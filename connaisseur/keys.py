import base64
import hashlib
import re
import binascii

import ecdsa
import rsa
from pyasn1.error import PyAsn1Error

from connaisseur.image import Image
from connaisseur.exceptions import NoSuchClassError, WrongKeyError

KMS_REGEX = r"(?:awskms|gcpkms|azurekms|hashivault|k8s):\/{2,3}[a-zA-Z0-9_.+\/:-]+"
KEYLESS_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"


class Key:
    """
    Abstract Key class, containing the public key used for verifying the image signatures.
    """

    value: str

    def __new__(cls, data: str):
        try:
            key_cls = Key.__get_key_type_cls(data)
            return super(Key, cls).__new__(key_cls)
        except Exception as err:
            msg = "Unable to find find class {class_name}."
            raise NoSuchClassError(message=msg, class_name=key_cls) from err

    @staticmethod
    def __get_key_type_cls(data: str):
        # key gets automatically identified
        if re.match(KEYLESS_REGEX, data):
            return KeyLessKey
        elif re.match(KMS_REGEX, data):
            return KMSKey
        elif Key.__is_ecdsa_key(data):
            return ECDSAKey
        elif Key.__is_rsa_key(data):
            return RSAKey
        return None

    @staticmethod
    def __is_ecdsa_key(data: str):
        try:
            ecdsa.VerifyingKey.from_pem(data)
            return True
        except (ecdsa.der.UnexpectedDER, binascii.Error, TypeError, AttributeError):
            return False

    @staticmethod
    def __is_rsa_key(data: str):
        try:
            rsa.PublicKey.load_pkcs1_openssl_pem(data)
            return True
        except (ValueError, PyAsn1Error):
            return False

    def verify(self, validator_type: str, **kwargs):  # pylint: disable=unused-argument
        msg = (
            "The key type {key_type} is unsupported for a validator of type {val_type}."
        )
        raise WrongKeyError(message=msg, key_type=type(self), val_type=validator_type)

    def __str__(self) -> str:
        return self.value


class ECDSAKey(Key):
    def __init__(self, data: str) -> None:
        self.value = ecdsa.VerifyingKey.from_pem(data)

    def verify(self, validator_type: str, **kwargs):
        if validator_type == "notaryv1":
            return self.__verify_notaryv1(**kwargs)
        elif validator_type == "cosign":
            return self.__verify_cosign(**kwargs)
        return super().verify(validator_type, **kwargs)

    def __verify_notaryv1(self, signature: str, payload: str):
        signature_decoded = base64.b64decode(signature)
        payload_bytes = bytearray(payload, "utf-8")
        return self.value.verify(
            signature_decoded, payload_bytes, hashfunc=hashlib.sha256
        )

    def __verify_cosign(self, cosign_callback, image: Image):
        return cosign_callback(image, ["--key", "/dev/stdin", self.value.to_pem()])

    def __str__(self) -> str:
        return base64.b64encode(self.value.to_der()).decode("utf-8")


class RSAKey(Key):
    def __init__(self, data: str) -> None:
        self.value = rsa.PublicKey.load_pkcs1_openssl_pem(data)

    def verify(self, validator_type: str, **kwargs):
        if validator_type == "notaryv1":
            pass
        elif validator_type == "cosign":
            pass
        return super().verify(validator_type, **kwargs)

    def __verify_cosign(
        self, cosign_callback, image: Image
    ):  # pylint: disable=unused-private-member
        return cosign_callback(image, ["--key", "/dev/stdin", self.value.save_pkcs1()])

    def __str__(self) -> str:
        return base64.b64encode(self.value.save_pkcs1("DER")).decode("utf-8")


class KMSKey(Key):
    def __init__(self, data: str) -> None:
        self.value = data

    def verify(self, validator_type: str, **kwargs):
        if validator_type == "cosign":
            return self.__verify_cosign(**kwargs)
        return super().verify(validator_type, **kwargs)

    def __verify_cosign(self, cosign_callback, image: Image):
        return cosign_callback(image, ["--key", self.value, b""])


class KeyLessKey(Key):
    def __init__(self, data: str) -> None:
        self.value = data

    def verify(self, validator_type: str, **kwargs):
        if validator_type == "cosign":
            pass
        return super().verify(validator_type, **kwargs)

    def __verify_cosign(
        self, cosign_callback, image: Image
    ):  # pylint: disable=unused-private-member
        return cosign_callback(image, ["--cert-email", self.value, b""])
