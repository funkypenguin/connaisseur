import json
import logging
import os
import re
import subprocess  # nosec

from connaisseur.exceptions import (
    CosignError,
    CosignTimeout,
    NotFoundException,
    InvalidFormatException,
    UnexpectedCosignData,
    ValidationError,
)
from connaisseur.image import Image
from connaisseur.keys import Key
from connaisseur.util import safe_path_func  # nosec
from connaisseur.validators.interface import ValidatorInterface


class CosignValidator(ValidatorInterface):
    name: str
    trust_roots: list
    k8s_keychain: bool

    def __init__(self, name: str, trust_roots: list, auth: dict = None, **kwargs):
        super().__init__(name, **kwargs)
        self.trust_roots = trust_roots
        self.k8s_keychain = False if auth is None else auth.get("k8s_keychain", False)

    def __get_key(self, key_name: str = None):
        key_name = key_name or "default"
        try:
            key = next(
                key["key"] for key in self.trust_roots if key["name"] == key_name
            )
        except StopIteration as err:
            msg = 'Trust root "{key_name}" not configured for validator "{validator_name}".'
            raise NotFoundException(
                message=msg, key_name=key_name, validator_name=self.name
            ) from err
        return Key("".join(key))

    async def validate(
        self, image: Image, trust_root: str = None, **kwargs
    ):  # pylint: disable=arguments-differ
        key = self.__get_key(trust_root)
        return self.__get_cosign_validated_digests(image, key).pop()

    def __get_cosign_validated_digests(self, image: Image, key: Key):
        """
        Get and process Cosign validation output for a given `image` and `key`
        and either return a list of valid digests or raise a suitable exception
        in case no valid signature is found or Cosign fails.
        """
        returncode, stdout, stderr = key.verify(
            validator_type="cosign", cosign_callback=self.__cosign_callback, image=image
        )
        logging.info(
            "COSIGN output for image: %s; RETURNCODE: %s; STDOUT: %s; STDERR: %s",
            image,
            returncode,
            stdout,
            stderr,
        )
        digests = []
        if returncode == 0:
            for sig in stdout.splitlines():
                try:
                    sig_data = json.loads(sig)
                    try:
                        digest = sig_data["critical"]["image"].get(
                            "docker-manifest-digest", ""
                        )
                        if re.match(r"sha256:[0-9A-Fa-f]{64}", digest) is None:
                            msg = "Digest '{digest}' does not match expected digest pattern."
                            raise InvalidFormatException(message=msg, digest=digest)
                    except Exception as err:
                        msg = (
                            "Could not retrieve valid and unambiguous digest from data "
                            "received by Cosign: {err_type}: {err}"
                        )
                        raise UnexpectedCosignData(
                            message=msg, err_type=type(err).__name__, err=str(err)
                        ) from err
                    # remove prefix 'sha256'
                    digests.append(digest.removeprefix("sha256:"))
                except json.JSONDecodeError:
                    logging.info("non-json signature data from Cosign: %s", sig)
                    pass
        elif "Error: no matching signatures:\nfailed to verify signature\n" in stderr:
            msg = "Failed to verify signature of trust data."
            raise ValidationError(
                message=msg,
                trust_data_type="dev.cosignproject.cosign/signature",
                stderr=stderr,
            )
        elif "Error: no matching signatures:\n\nmain.go:" in stderr:
            msg = 'No trust data for image "{image}".'
            raise NotFoundException(
                message=msg,
                trust_data_type="dev.cosignproject.cosign/signature",
                stderr=stderr,
                image=str(image),
            )
        else:
            msg = 'Unexpected Cosign exception for image "{image}": {stderr}.'
            raise CosignError(
                message=msg,
                trust_data_type="dev.cosignproject.cosign/signature",
                stderr=stderr,
                image=str(image),
            )
        if not digests:
            msg = (
                "Could not extract any digest from data received by Cosign "
                "despite successful image verification."
            )
            raise UnexpectedCosignData(message=msg)
        return digests

    def __cosign_callback(self, image: Image, key_args: list):
        """
        Callback function that is passed on to any `key.verify()` that is using a cosign
        validator. Invokes the actual cosign command with different arguments, depending
        on specific key at hand.
        """
        option_kword, inline_key, key = key_args
        cmd = [
            "/app/cosign/cosign",
            "verify",
            "--output",
            "text",
            option_kword,
            inline_key,
            *(["--k8s-keychain"] if self.k8s_keychain else []),
            str(image),
        ]

        with subprocess.Popen(  # nosec
            cmd,
            env=self.__get_envs(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as process:
            try:
                stdout, stderr = process.communicate(key, timeout=60)
            except subprocess.TimeoutExpired as err:
                process.kill()
                msg = "Cosign timed out."
                raise CosignTimeout(
                    message=msg, trust_data_type="dev.cosignproject.cosign/signature"
                ) from err

        return process.returncode, stdout.decode("utf-8"), stderr.decode("utf-8")

    def __get_envs(self):
        """
        Sets up environment variables used by cosign for potential authentication or TLS
        verification against private registries.
        """
        env = os.environ.copy()
        # Extend the OS env vars only for passing to the subprocess below
        env["DOCKER_CONFIG"] = f"/app/connaisseur-config/{self.name}/.docker/"
        if safe_path_func(
            os.path.exists, "/app/certs/cosign", f"/app/certs/cosign/{self.name}.crt"
        ):
            env["SSL_CERT_FILE"] = f"/app/certs/cosign/{self.name}.crt"
        return env

    @property
    def healthy(self):
        return True
