import pytest
from . import conftest as fix
import connaisseur.exceptions as exc
import connaisseur.keys as keys
from connaisseur.image import Image


sample_ecdsa = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOXYta5TgdCwXTCnLU09W5T4M4r9f\nQQrqJuADP6U7g5r9ICgPSmZuRHP/1AYUfOQW3baveKsT969EfELKj1lfCA==\n-----END PUBLIC KEY-----"
sample_rsa = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs5pC7R5OTSTUMJHUniPk\nrLfmGDAUxZtRlvIE+pGPCD6cUXH22advkK87xwpupjxdVYuKTFnWHUIyFJwjI3vu\nsievezcAr0E/xxyeo49tWog9kFoooK3qmXjpETC8OpvNROZ0K3qhlm9PZkGo3gSJ\n/B4rMU/d+jkCI8eiUPpdVQOczdBoD5nzQAF1mfmffWGsbKY+d8/l77Vset0GXExR\nzUtnglMhREyHNpDeQUg5OEn+kuGLlTzIxpIF+MlbzP3+xmNEzH2iafr0ae2g5kX2\n880priXpxG8GXW2ybZmPvchclnvFu4ZfZcM10FpgYJFvR/9iofFeAka9u5z6VZcc\nmQIDAQAB\n-----END PUBLIC KEY-----"
awskms1 = "awskms:///1234abcd-12ab-34cd-56ef-1234567890ab"
awskms2 = "awskms://localhost:4566/1234abcd-12ab-34cd-56ef-1234567890ab"
awskms3 = "awskms:///arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
awskms4 = "awskms://localhost:4566/arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
awskms5 = "awskms:///alias/ExampleAlias"
awskms6 = "awskms://localhost:4566/alias/ExampleAlias"
awskms7 = "awskms:///arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias"
awskms8 = (
    "awskms://localhost:4566/arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias"
)
gcpkms = "gcpkms://projects/example_project/locations/example_location/keyRings/example_keyring/cryptoKeys/example_key/versions/example_keyversion"
azurekms = "azurekms://example_vault_name/example_key"
hashicorpkms = "hashivault://example_keyname"
k8skms = "k8s://example_ns/example_key"
sample_mail = "mail@example.com"

sample_ecdsa2 = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEi2WD/E/UXF4+yoE5e4cjpJMNgQw\n8PAVALRX+8f8I8B+XneAtnOHDTI8L6wBeFRTzl6G4OmgDyCRYTb5MV3hog==\n-----END PUBLIC KEY-----"
sample_ecdsa_sig = "hx/VtTJT2r1nmkHtPZacncvosKca4XnLbMxNmeuH0cw5sTsUsznRuZmgd4vKPaQUbnCA3RMQpNlaGRWz1TR8CQ=="


def cb(image, key_args):
    return key_args[:2]


@pytest.mark.parametrize(
    "data, class_, exception",
    [
        (sample_ecdsa, keys.ECDSAKey, fix.no_exc()),
        (sample_rsa, keys.RSAKey, fix.no_exc()),
        (sample_mail, keys.KeyLessKey, fix.no_exc()),
        ("iamnotakey", None, pytest.raises(exc.NoSuchClassError)),
    ]
    + list(
        map(
            lambda x: (x, keys.KMSKey, fix.no_exc()),
            [
                awskms1,
                awskms2,
                awskms3,
                awskms4,
                awskms5,
                awskms6,
                awskms7,
                awskms8,
                gcpkms,
                azurekms,
                hashicorpkms,
                k8skms,
            ],
        )
    ),
)
def test_keys(data, class_, exception):
    with exception:
        key = keys.Key(data)
        assert isinstance(key, class_)


@pytest.mark.parametrize(
    "key, validator_type, exception, kwargs, out",
    [
        (
            sample_ecdsa2,
            "notaryv1",
            fix.no_exc(),
            {"signature": sample_ecdsa_sig, "payload": "iliketurtles"},
            True,
        ),
        (
            sample_ecdsa,
            "cosign",
            fix.no_exc(),
            {"image": Image("testimage:test"), "cosign_callback": cb},
            ["--key", "/dev/stdin"],
        ),
        (sample_rsa, "notaryv1", pytest.raises(exc.WrongKeyError), {}, []),
        # (
        #     sample_rsa,
        #     "cosign",
        #     fix.no_exc(),
        #     {"image": Image("testimage:test"), "cosign_callback": cb},
        #     ["--key", "/dev/stdin"],
        # ),
        (
            awskms1,
            "cosign",
            fix.no_exc(),
            {"image": "testimage:test", "cosign_callback": cb},
            ["--key", awskms1],
        ),
        # (
        #     sample_mail,
        #     "cosign",
        #     fix.no_exc(),
        #     {"image": "testimage:test", "cosign_callback": cb},
        #     ["--cert-email", sample_mail],
        # ),
    ]
    + list(
        map(
            lambda x: (x, "unknown_type", pytest.raises(exc.WrongKeyError), {}, []),
            [sample_ecdsa, sample_rsa, awskms1, sample_mail],
        )
    ),
)
def test_verify(key, validator_type, exception, kwargs, out):
    k = keys.Key(key)
    with exception:
        assert k.verify(validator_type=validator_type, **kwargs) == out


@pytest.mark.parametrize(
    "key, out",
    [
        (
            sample_ecdsa,
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOXYta5TgdCwXTCnLU09W5T4M4r9fQQrqJuADP6U7g5r9ICgPSmZuRHP/1AYUfOQW3baveKsT969EfELKj1lfCA==",
        ),
        (
            sample_rsa,
            "MIIBCgKCAQEAs5pC7R5OTSTUMJHUniPkrLfmGDAUxZtRlvIE+pGPCD6cUXH22advkK87xwpupjxdVYuKTFnWHUIyFJwjI3vusievezcAr0E/xxyeo49tWog9kFoooK3qmXjpETC8OpvNROZ0K3qhlm9PZkGo3gSJ/B4rMU/d+jkCI8eiUPpdVQOczdBoD5nzQAF1mfmffWGsbKY+d8/l77Vset0GXExRzUtnglMhREyHNpDeQUg5OEn+kuGLlTzIxpIF+MlbzP3+xmNEzH2iafr0ae2g5kX2880priXpxG8GXW2ybZmPvchclnvFu4ZfZcM10FpgYJFvR/9iofFeAka9u5z6VZccmQIDAQAB",
        ),
        (awskms1, awskms1),
        (sample_mail, sample_mail),
    ],
)
def test_str(key, out):
    k = keys.Key(key)
    assert str(k) == out
