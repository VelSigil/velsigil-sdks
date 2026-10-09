"""Classify every vector in sdks/test-vectors.json."""

from __future__ import annotations

import base64
import copy
import hashlib
import inspect
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import mock_server as ms  # noqa: E402

from velsigil_client import (  # noqa: E402
    LEASE_REVOKING_CODES,
    Code,
    ConfigurationError,
    CryptoBackendError,
    Ed25519Verifier,
    EnvelopeError,
    HardwareIdError,
    LeaseError,
    LicenseInfo,
    hwid_from_machine_id,
    key_id_for,
    open_envelope,
    verify_lease,
)
from velsigil_client import client as client_module, crypto, hwid  # noqa: E402

VECTORS = ms.VECTORS

# The public helpers refuse the published test keys, so the vectors use the internal paths.
vector_verifier = crypto._new_verifier
open_vector_envelope = crypto._open_envelope
verify_vector_lease = crypto._verify_lease


def classify_envelope(verifier, vector, hwid=None):
    """``hwid`` defaults to the vector's own ``hwid``, if any."""
    try:
        payload = open_vector_envelope(
            verifier,
            vector["envelope"],
            vector["requestNonce"],
            vector["productId"],
            vector["requestType"],
            expected_hwid=hwid if hwid is not None else vector.get("hwid"),
        )
    except EnvelopeError as exc:
        return exc.reason, None
    return "valid", payload


def classify_lease(verifier, vector):
    try:
        payload = verify_vector_lease(verifier, vector["token"], vector["productId"], vector["hwid"], vector["now"])
    except LeaseError as exc:
        return exc.reason, None
    return "valid", payload


def _backends():
    names = ["cryptography"]
    try:
        import nacl.signing  # noqa: F401
    except ImportError:
        pass
    else:
        names.append("nacl")
    return names


class KeyTests(unittest.TestCase):
    def test_vector_keys_are_consistent(self):
        self.assertEqual(ms.public_key_b64(ms.SEED), VECTORS["keys"]["publicKey"])
        self.assertEqual(ms.public_key_b64(ms.WRONG_SEED), VECTORS["keys"]["wrongPublicKey"])
        verifier = vector_verifier(VECTORS["keys"]["publicKey"])
        self.assertIsInstance(verifier, Ed25519Verifier)
        self.assertEqual(verifier.key_id, VECTORS["keys"]["keyId"])
        raw = crypto._decode_public_key(VECTORS["keys"]["publicKey"])
        self.assertEqual(hashlib.sha256(raw).hexdigest()[:16], VECTORS["keys"]["keyId"])

    def test_public_key_parsing(self):
        for key, make in ((ms.generate_public_key_b64(), Ed25519Verifier), (VECTORS["keys"]["publicKey"], vector_verifier)):
            raw = base64.b64decode(key)
            self.assertEqual(make(key.rstrip("=")).public_key_bytes, raw)
            self.assertEqual(make("  " + key + "\n").public_key_bytes, raw)
            for bad in ("", "not base64!", "AAAA", key[:-8], key + "AAAA", None):
                with self.subTest(make=make.__name__, bad=bad):
                    with self.assertRaises(ConfigurationError):
                        make(bad)  # type: ignore[arg-type]

    def test_unknown_backend_rejected(self):
        with self.assertRaises(ConfigurationError):
            Ed25519Verifier(ms.generate_public_key_b64(), backend="openssl-cli")
        with self.assertRaises(ConfigurationError):
            vector_verifier(VECTORS["keys"]["publicKey"], backend="openssl-cli")

    def test_backend_fallback_and_missing_backend(self):
        key = VECTORS["keys"]["publicKey"]

        def unavailable(raw):
            raise ImportError("simulated missing package")

        with mock.patch.object(crypto, "_cryptography_verifier", unavailable):
            with self.assertRaises(CryptoBackendError):
                vector_verifier(key, backend="cryptography")
            with self.assertRaises(CryptoBackendError):
                Ed25519Verifier(ms.generate_public_key_b64(), backend="cryptography")
            with mock.patch.object(crypto, "_nacl_verifier", unavailable):
                with self.assertRaises(CryptoBackendError):
                    vector_verifier(key)
            with mock.patch.object(crypto, "_nacl_verifier", lambda raw: (lambda sig, msg: False)):
                verifier = vector_verifier(key)
                self.assertEqual(verifier.backend, "nacl")
                self.assertEqual(classify_envelope(verifier, VECTORS["envelopes"][0])[0], "invalid_signature")


class PublishedTestKeyHelperTests(unittest.TestCase):
    """The public helpers refuse both published test keys on any host."""

    MESSAGE = (
        "This is the public test key from the Velsigil SDK test vectors, whose private key is published: "
        "anyone could forge license answers for it. Use your product's public key "
        "(panel: Products > your product > Integration)."
    )
    KEYS = ((VECTORS["keys"]["publicKey"], ms.SEED), (VECTORS["keys"]["wrongPublicKey"], ms.WRONG_SEED))
    NOW = 1_800_000_000

    @staticmethod
    def spellings(key):
        """Other accepted spellings of the same key bytes, including non-canonical base64."""
        body = key.rstrip("=")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        non_canonical = body[:-1] + alphabet[alphabet.index(body[-1]) ^ 1] + "="
        spellings = [key, body, "  " + key + "\n", " " + body + "\t"]
        try:
            if crypto._decode_public_key(non_canonical) == crypto._decode_public_key(key):
                spellings.append(non_canonical)
        except ConfigurationError:
            pass
        return spellings

    def assertRefused(self, call):
        with self.assertRaises(ConfigurationError) as caught:
            call()
        self.assertEqual(str(caught.exception), self.MESSAGE)
        self.assertEqual(caught.exception.code, Code.INVALID_CONFIGURATION)
        self.assertIsInstance(caught.exception, ValueError)

    def test_constant_matches_the_vectors_file(self):
        self.assertEqual(client_module._PUBLISHED_TEST_PUBLIC_KEYS, {base64.b64decode(key) for key, _ in self.KEYS})
        self.assertFalse(hasattr(crypto, "_PUBLISHED_TEST_PUBLIC_KEYS"))

    def test_key_helpers_refuse_both_test_keys(self):
        for key, _ in self.KEYS:
            spellings = self.spellings(key)
            self.assertGreaterEqual(len(spellings), 4)
            for spelling in spellings:
                with self.subTest(key=spelling):
                    for backend in ["auto"] + _backends():
                        self.assertRefused(lambda: Ed25519Verifier(spelling, backend=backend))
                    self.assertRefused(lambda: key_id_for(spelling))
                    self.assertRefused(lambda: crypto.decode_public_key(spelling))

    def test_refusal_is_the_invalid_key_error(self):
        for helper in (Ed25519Verifier, key_id_for, crypto.decode_public_key):
            with self.subTest(helper=helper.__name__):
                with self.assertRaises(ConfigurationError) as bad_key:
                    helper("short")
                with self.assertRaises(ConfigurationError) as test_key:
                    helper(self.KEYS[0][0])
                self.assertIs(type(test_key.exception), type(bad_key.exception))
                self.assertEqual(test_key.exception.code, bad_key.exception.code)

    def test_verification_helpers_refuse_a_verifier_holding_a_test_key(self):
        vector = {v["name"]: v for v in VECTORS["envelopes"]}["validate_ok"]
        for key, seed in self.KEYS:
            with self.subTest(key=key):
                verifier = vector_verifier(key)
                envelope = ms.sign_envelope(vector["payload"], seed)
                args = (envelope, vector["requestNonce"], vector["productId"], vector["requestType"])
                token = ms.make_lease(self.NOW + 3600, seed_b64=seed)
                self.assertEqual(open_vector_envelope(verifier, *args), vector["payload"])
                claims = verify_vector_lease(verifier, token, ms.PRODUCT_ID, ms.TEST_HWID, self.NOW)
                self.assertEqual(claims["exp"], self.NOW + 3600)
                self.assertRefused(lambda: open_envelope(verifier, *args))
                self.assertRefused(lambda: open_envelope(verifier, *args, expected_hwid=ms.TEST_HWID))
                self.assertRefused(lambda: open_envelope(verifier, None, "n", "p", None))  # type: ignore[arg-type]
                self.assertRefused(lambda: verify_lease(verifier, token, ms.PRODUCT_ID, ms.TEST_HWID, self.NOW))
                self.assertRefused(lambda: verify_lease(verifier, "not a lease", ms.PRODUCT_ID, ms.TEST_HWID, self.NOW))

    def test_internal_path_verifies_the_vectors(self):
        verifier = vector_verifier(VECTORS["keys"]["publicKey"])
        by_name = {v["name"]: v for v in VECTORS["envelopes"]}
        self.assertEqual(classify_envelope(verifier, by_name["validate_ok"]), ("valid", by_name["validate_ok"]["payload"]))
        self.assertEqual(classify_envelope(verifier, by_name["wrong_key"])[0], "invalid_signature")
        self.assertEqual(classify_envelope(verifier, by_name["validate_lease_other_device"])[0], "hwid_mismatch")
        lease = VECTORS["leases"][0]
        self.assertEqual(classify_lease(verifier, lease), ("valid", lease["payload"]))

    def test_public_helpers_have_no_opt_out(self):
        expected = {
            Ed25519Verifier: ["public_key_base64", "backend"],
            key_id_for: ["public_key_base64"],
            crypto.decode_public_key: ["public_key_base64"],
            open_envelope: ["verifier", "envelope", "expected_nonce", "expected_product_id", "expected_type", "expected_hwid"],
            verify_lease: ["verifier", "token", "product_id", "hwid", "now"],
        }
        for helper, names in expected.items():
            with self.subTest(helper=helper.__name__):
                self.assertEqual(list(inspect.signature(helper).parameters), names)
        for name in ("_new_verifier", "_open_envelope", "_verify_lease", "_decode_public_key"):
            self.assertNotIn(name, crypto.__all__)

    def test_public_helpers_accept_real_keys(self):
        seed = base64.b64encode(os.urandom(32)).decode("ascii")
        key = ms.public_key_b64(seed)
        raw = base64.b64decode(key)
        self.assertFalse(crypto._is_published_test_key(raw))
        verifier = Ed25519Verifier(key)
        self.assertEqual(crypto.decode_public_key(key), raw)
        self.assertEqual(key_id_for(key), hashlib.sha256(raw).hexdigest()[:16])
        self.assertEqual(verifier.key_id, key_id_for(key))
        vector = {v["name"]: v for v in VECTORS["envelopes"]}["validate_ok"]
        args = (vector["requestNonce"], vector["productId"], vector["requestType"])
        self.assertEqual(open_envelope(verifier, ms.sign_envelope(vector["payload"], seed), *args), vector["payload"])
        with self.assertRaises(EnvelopeError) as caught:
            open_envelope(verifier, vector["envelope"], *args)
        self.assertEqual(caught.exception.reason, "invalid_signature")
        token = ms.make_lease(self.NOW + 3600, seed_b64=seed)
        self.assertEqual(verify_lease(verifier, token, ms.PRODUCT_ID, ms.TEST_HWID, self.NOW)["exp"], self.NOW + 3600)


class EnvelopeVectorTests(unittest.TestCase):
    def test_every_envelope_vector(self):
        self.assertGreaterEqual(len(VECTORS["envelopes"]), 11)
        for backend in _backends():
            verifier = vector_verifier(VECTORS["keys"]["publicKey"], backend=backend)
            for vector in VECTORS["envelopes"]:
                with self.subTest(backend=backend, vector=vector["name"]):
                    outcome, payload = classify_envelope(verifier, vector)
                    self.assertEqual(outcome, vector["expect"])
                    if outcome == "valid":
                        self.assertEqual(payload, vector["payload"])

    def test_device_binding_vectors_are_authentic(self):
        verifier = vector_verifier(VECTORS["keys"]["publicKey"])
        bound = [v for v in VECTORS["envelopes"] if v["expect"] == "hwid_mismatch"]
        self.assertEqual(
            sorted(v["name"] for v in bound),
            ["validate_activation_other_device", "validate_lease_other_device"],
        )
        owners = {
            "validate_lease_other_device": "test-hwid-0001-abcdef",
            "validate_activation_other_device": "test-hwid-9999-zzzzzz",
        }
        for vector in bound:
            with self.subTest(vector=vector["name"]):
                unbound = dict(vector)
                del unbound["hwid"]
                outcome, payload = classify_envelope(verifier, unbound)
                self.assertEqual(outcome, "valid")
                self.assertEqual(payload, vector["payload"])
                self.assertEqual(classify_envelope(verifier, vector, hwid=owners[vector["name"]])[0], "valid")
                self.assertEqual(ms.encode_payload(vector["payload"]), vector["envelope"]["data"])
        by_name = {v["name"]: v for v in VECTORS["envelopes"]}
        self.assertEqual(by_name["validate_ok"]["hwid"], ms.TEST_HWID)

    def test_server_encoding_and_signing_reproduce_valid_vectors(self):
        for vector in VECTORS["envelopes"]:
            if vector["expect"] != "valid":
                continue
            with self.subTest(vector=vector["name"]):
                self.assertEqual(ms.encode_payload(vector["payload"]), vector["envelope"]["data"])
                self.assertEqual(ms.sign_text(vector["envelope"]["data"]), vector["envelope"]["sig"])

    def test_kid_is_ignored_for_key_selection(self):
        verifier = vector_verifier(VECTORS["keys"]["publicKey"])
        by_name = {v["name"]: v for v in VECTORS["envelopes"]}
        valid = copy.deepcopy(by_name["validate_ok"])
        valid["envelope"]["kid"] = "ffffffffffffffff"
        self.assertEqual(classify_envelope(verifier, valid)[0], "valid")
        del valid["envelope"]["kid"]
        self.assertEqual(classify_envelope(verifier, valid)[0], "valid")
        forged = copy.deepcopy(by_name["wrong_key"])
        forged["envelope"]["kid"] = VECTORS["keys"]["keyId"]
        self.assertEqual(classify_envelope(verifier, forged)[0], "invalid_signature")

    def test_signature_padding_is_tolerated(self):
        verifier = vector_verifier(VECTORS["keys"]["publicKey"])
        vector = copy.deepcopy(VECTORS["envelopes"][0])
        vector["envelope"]["sig"] += "=="
        self.assertEqual(classify_envelope(verifier, vector)[0], "valid")

    def test_structurally_broken_envelopes(self):
        verifier = vector_verifier(VECTORS["keys"]["publicKey"])
        good = VECTORS["envelopes"][0]
        cases = {
            "not a dict": ([good["envelope"]], "malformed"),
            "no data": ({"sig": good["envelope"]["sig"]}, "invalid_signature"),
            "sig not a string": ({"data": good["envelope"]["data"], "sig": 5}, "invalid_signature"),
            "sig not base64url": ({"data": good["envelope"]["data"], "sig": "!!!"}, "invalid_signature"),
            "non-ascii data": ({"data": good["envelope"]["data"] + "é", "sig": good["envelope"]["sig"]}, "invalid_signature"),
            "empty data": ({"data": "", "sig": good["envelope"]["sig"]}, "invalid_signature"),
        }
        for name, (envelope, expected) in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(EnvelopeError) as ctx:
                    open_vector_envelope(verifier, envelope, good["requestNonce"], good["productId"], good["requestType"])
                self.assertEqual(ctx.exception.reason, expected)

    def test_signed_but_unparseable_payload_is_malformed(self):
        verifier = vector_verifier(VECTORS["keys"]["publicKey"])
        for data in (ms.b64url(b"not json"), ms.b64url(b"[1,2]"), ms.b64url(b'{"v":2}'), "@@@@"):
            with self.subTest(data=data):
                envelope = {"data": data, "sig": ms.sign_text(data)}
                with self.assertRaises(EnvelopeError) as ctx:
                    open_vector_envelope(verifier, envelope, "n", ms.PRODUCT_ID, "validate")
                self.assertEqual(ctx.exception.reason, "malformed")

    def test_type_mismatch(self):
        verifier = vector_verifier(VECTORS["keys"]["publicKey"])
        vector = VECTORS["envelopes"][0]
        with self.assertRaises(EnvelopeError) as ctx:
            open_vector_envelope(verifier, vector["envelope"], vector["requestNonce"], vector["productId"], "deactivate")
        self.assertEqual(ctx.exception.reason, "type_mismatch")
        payload = open_vector_envelope(verifier, vector["envelope"], vector["requestNonce"], vector["productId"], "validate")
        self.assertTrue(payload["ok"])

    def test_type_mismatch_vector_is_authentic(self):
        verifier = vector_verifier(VECTORS["keys"]["publicKey"])
        vector = {v["name"]: v for v in VECTORS["envelopes"]}["type_mismatch"]
        self.assertEqual(vector["requestType"], "validate")
        self.assertEqual((vector["payload"]["type"], vector["payload"]["ok"]), ("update_check", True))
        self.assertEqual(classify_envelope(verifier, vector)[0], "type_mismatch")
        payload = open_vector_envelope(
            verifier, vector["envelope"], vector["requestNonce"], vector["productId"], "update_check", vector["hwid"]
        )
        self.assertEqual(payload, vector["payload"])
        self.assertEqual(ms.encode_payload(vector["payload"]), vector["envelope"]["data"])

    def test_expected_type_is_required(self):
        verifier = vector_verifier(VECTORS["keys"]["publicKey"])
        vector = {v["name"]: v for v in VECTORS["envelopes"]}["type_mismatch"]
        args = (verifier, vector["envelope"], vector["requestNonce"], vector["productId"])
        with self.assertRaises(TypeError):
            open_vector_envelope(*args)  # type: ignore[call-arg]
        for missing in (None, "", 5):
            with self.subTest(expected_type=missing):
                with self.assertRaises(ValueError):
                    open_vector_envelope(*args, missing)  # type: ignore[arg-type]
                with self.assertRaises(ValueError):
                    open_vector_envelope(*args, expected_type=missing, expected_hwid=vector["hwid"])  # type: ignore[arg-type]


class LeaseVectorTests(unittest.TestCase):
    def test_every_lease_vector(self):
        self.assertGreaterEqual(len(VECTORS["leases"]), 8)
        for backend in _backends():
            verifier = vector_verifier(VECTORS["keys"]["publicKey"], backend=backend)
            for vector in VECTORS["leases"]:
                with self.subTest(backend=backend, vector=vector["name"]):
                    outcome, payload = classify_lease(verifier, vector)
                    self.assertEqual(outcome, vector["expect"])
                    if outcome == "valid":
                        self.assertEqual(payload, vector["payload"])

    def test_expiry_boundary(self):
        verifier = vector_verifier(VECTORS["keys"]["publicKey"])
        vector = VECTORS["leases"][0]
        exp = vector["payload"]["exp"]
        self.assertEqual(classify_lease(verifier, dict(vector, now=exp - 1))[0], "valid")
        self.assertEqual(classify_lease(verifier, dict(vector, now=exp))[0], "expired")

    def test_lease_signature_padding_is_tolerated(self):
        verifier = vector_verifier(VECTORS["keys"]["publicKey"])
        vector = dict(VECTORS["leases"][0])
        vector["token"] += "=="
        self.assertEqual(classify_lease(verifier, vector)[0], "valid")

    def test_malformed_tokens(self):
        verifier = vector_verifier(VECTORS["keys"]["publicKey"])
        base = VECTORS["leases"][0]
        body, sig = base["token"].split(".")
        for token in ("", ".", body + ".", "." + sig, body + "." + sig + ".x", None, 42):
            with self.subTest(token=token):
                self.assertEqual(classify_lease(verifier, dict(base, token=token))[0], "malformed")

    def test_signed_lease_without_required_claims_is_malformed(self):
        verifier = vector_verifier(VECTORS["keys"]["publicKey"])
        body = ms.encode_payload({"v": 1, "typ": "lease", "productId": ms.PRODUCT_ID})
        token = body + "." + ms.sign_text(body)
        self.assertEqual(
            classify_lease(verifier, {"token": token, "productId": ms.PRODUCT_ID, "hwid": ms.TEST_HWID, "now": 0})[0],
            "malformed",
        )


class FreeTrialVectorTests(unittest.TestCase):
    """The optional signed ``trial`` field, ``trial_already_used`` and unknown fields."""

    def setUp(self):
        self.verifier = vector_verifier(VECTORS["keys"]["publicKey"])
        self.by_name = {v["name"]: v for v in VECTORS["envelopes"]}
        self.leases = {v["name"]: v for v in VECTORS["leases"]}

    def test_trial_license_flag(self):
        outcome, payload = classify_envelope(self.verifier, self.by_name["validate_ok_trial"])
        self.assertEqual(outcome, "valid")
        self.assertTrue(LicenseInfo.from_payload(payload["license"], granted=True).is_trial)
        outcome, payload = classify_envelope(self.verifier, self.by_name["validate_ok"])
        self.assertNotIn("trial", payload["license"])
        self.assertFalse(LicenseInfo.from_payload(payload["license"]).is_trial)

    def test_trial_already_used(self):
        outcome, payload = classify_envelope(self.verifier, self.by_name["trial_already_used"])
        self.assertEqual(outcome, "valid")
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], Code.TRIAL_ALREADY_USED)
        self.assertNotIn(Code.TRIAL_ALREADY_USED, LEASE_REVOKING_CODES)

    def test_unknown_fields_are_ignored(self):
        vector = self.by_name["unknown_fields"]
        self.assertEqual(vector["unknownFields"], ["futureField", "license.futureLicenseField"])
        outcome, payload = classify_envelope(self.verifier, vector)
        self.assertEqual(outcome, "valid")
        info = LicenseInfo.from_payload(payload["license"], granted=True)
        self.assertFalse(info.is_trial)
        self.assertEqual(classify_lease(self.verifier, self.leases["lease_unknown_fields"])[0], "valid")

    def test_trial_lease_flag(self):
        outcome, claims = classify_lease(self.verifier, self.leases["lease_trial"])
        self.assertEqual(outcome, "valid")
        self.assertIs(claims["trial"], True)

    def test_non_boolean_trial_is_malformed(self):
        license_obj = dict(self.by_name["validate_ok"]["payload"]["license"], trial="yes")
        with self.assertRaises(ValueError):
            LicenseInfo.from_payload(license_obj)

    def test_trial_conversion_reference(self):
        from velsigil_client import TRIAL_REF_PARAM, with_trial_ref
        from velsigil_client.client import _result_from_payload

        for name in ("validate_ok_trial_ref", "license_expired_trial_ref"):
            with self.subTest(name=name):
                outcome, payload = classify_envelope(self.verifier, self.by_name[name])
                self.assertEqual(outcome, "valid")
                ref = payload["license"]["trialRef"]
                self.assertTrue(ref.startswith("vtr1_"))
                result = _result_from_payload(payload)
                self.assertEqual(result.trial_ref, ref)
                self.assertEqual(result.license.trial_ref, ref)
                self.assertEqual(result.with_trial_ref("https://shop.example.com/buy"), "https://shop.example.com/buy?velsigil_trial=" + ref)
        expired = _result_from_payload(classify_envelope(self.verifier, self.by_name["license_expired_trial_ref"])[1])
        self.assertFalse(expired.ok)
        self.assertEqual(expired.code, "license_expired")
        plain = _result_from_payload(classify_envelope(self.verifier, self.by_name["validate_ok_trial"])[1])
        self.assertIsNone(plain.trial_ref)
        self.assertEqual(plain.with_trial_ref("https://shop.example.com/buy"), "https://shop.example.com/buy")
        ref = self.by_name["validate_ok_trial_ref"]["payload"]["license"]["trialRef"]
        self.assertEqual(TRIAL_REF_PARAM, "velsigil_trial")
        self.assertEqual(with_trial_ref("https://shop.example.com/buy?plan=pro#top", ref), "https://shop.example.com/buy?plan=pro&velsigil_trial=" + ref + "#top")
        self.assertEqual(with_trial_ref("https://shop.example.com/buy?", ref), "https://shop.example.com/buy?velsigil_trial=" + ref)
        self.assertEqual(with_trial_ref("https://buy.stripe.com/test_abc", ref), "https://buy.stripe.com/test_abc?client_reference_id=" + ref)
        self.assertEqual(with_trial_ref("mailto:sales@example.com", ref), "mailto:sales@example.com")
        self.assertEqual(with_trial_ref("https://shop.example.com/buy", "has space"), "https://shop.example.com/buy")
        for bad in (42, "", "has space", "x" * 201, "ünicode"):
            with self.subTest(bad=bad):
                license_obj = dict(self.by_name["validate_ok_trial"]["payload"]["license"], trialRef=bad)
                with self.assertRaises(ValueError):
                    LicenseInfo.from_payload(license_obj)


class InAppTrialVectorTests(unittest.TestCase):
    """Answers of type ``trial`` and the key of a started trial."""

    def setUp(self):
        self.verifier = vector_verifier(VECTORS["keys"]["publicKey"])
        self.by_name = {v["name"]: v for v in VECTORS["envelopes"]}

    def test_started_trial_carries_the_key(self):
        from velsigil_client.client import _result_from_payload

        outcome, payload = classify_envelope(self.verifier, self.by_name["trial_started"])
        self.assertEqual(outcome, "valid")
        result = _result_from_payload(payload)
        self.assertTrue(result.ok)
        self.assertEqual(result.trial_key, payload["trial"]["key"])
        self.assertTrue(result.is_trial)
        self.assertTrue(result.activation.device_secret_issued)

    def test_trial_failures_carry_no_key(self):
        from velsigil_client.client import _result_from_payload

        for name, code in (
            ("trial_start_already_used", Code.TRIAL_ALREADY_USED),
            ("trial_unavailable", Code.TRIAL_UNAVAILABLE),
            ("trial_confirmation_sent", Code.TRIAL_CONFIRMATION_SENT),
        ):
            with self.subTest(name=name):
                outcome, payload = classify_envelope(self.verifier, self.by_name[name])
                self.assertEqual(outcome, "valid")
                self.assertNotIn("trial", payload)
                result = _result_from_payload(payload)
                self.assertFalse(result.ok)
                self.assertEqual(result.code, code)
                self.assertIsNone(result.trial_key)

    def test_a_trial_answer_is_no_validation_and_the_other_way_round(self):
        self.assertEqual(classify_envelope(self.verifier, self.by_name["trial_answer_as_validate"])[0], "type_mismatch")
        started = dict(self.by_name["trial_started"], requestType="validate")
        self.assertEqual(classify_envelope(self.verifier, started)[0], "type_mismatch")
        validate_ok = dict(self.by_name["validate_ok_trial"], requestType="trial")
        self.assertEqual(classify_envelope(self.verifier, validate_ok)[0], "type_mismatch")

    def test_ok_trial_answer_without_a_key_is_malformed(self):
        from velsigil_client.client import _result_from_payload

        payload = copy.deepcopy(self.by_name["trial_started"]["payload"])
        del payload["trial"]
        with self.assertRaises(ValueError):
            _result_from_payload(payload)


class HwidTests(unittest.TestCase):
    def test_examples_reproduce_exactly(self):
        self.assertEqual(VECTORS["hwid"]["prefix"], hwid.HWID_PREFIX)
        for example in VECTORS["hwid"]["examples"]:
            with self.subTest(raw=example["machineIdRaw"]):
                self.assertEqual(hwid.normalize_machine_id(example["machineIdRaw"]), example["machineIdNormalized"])
                value = hwid_from_machine_id(example["machineIdRaw"])
                self.assertEqual(value, example["hwid"])
                self.assertEqual(hashlib.sha256(value.encode("utf-8")).hexdigest(), example["serverHwidHash"])
        sample = VECTORS["hwid"]["serverHashOfTestHwid"]
        self.assertEqual(crypto.sha256_hex(sample["hwid"]), sample["hwidHash"])

    def test_empty_machine_id_rejected(self):
        with self.assertRaises(ValueError):
            hwid_from_machine_id("  \n")

    def test_current_machine(self):
        try:
            value = hwid.get_hardware_id()
        except HardwareIdError as exc:
            self.skipTest("no machine id on this host: %s" % exc)
        self.assertRegex(value, r"^[0-9a-f]{64}$")
        self.assertEqual(value, hwid.get_hardware_id())

    def test_linux_machine_id_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = os.path.join(tmp, "machine-id")
            second = os.path.join(tmp, "dbus-machine-id")
            with open(second, "w", encoding="utf-8") as handle:
                handle.write("A1B2C3D4E5F60718293A4B5C6D7E8F90\n")
            with mock.patch.object(hwid, "_LINUX_MACHINE_ID_PATHS", (first, second)):
                raw = hwid.read_machine_id("linux")
                self.assertEqual(hwid_from_machine_id(raw), VECTORS["hwid"]["examples"][1]["hwid"])
            with open(first, "w", encoding="utf-8") as handle:
                handle.write("4C4C4544-0042-3510-8051-B4C04F4E4B32")
            with mock.patch.object(hwid, "_LINUX_MACHINE_ID_PATHS", (first, second)):
                self.assertEqual(hwid_from_machine_id(hwid.read_machine_id("linux")), VECTORS["hwid"]["examples"][0]["hwid"])
            with mock.patch.object(hwid, "_LINUX_MACHINE_ID_PATHS", (os.path.join(tmp, "missing"),)):
                with self.assertRaises(HardwareIdError):
                    hwid.read_machine_id("linux")

    def test_linux_machine_id_placeholder_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = os.path.join(tmp, "machine-id")
            second = os.path.join(tmp, "dbus-machine-id")
            with open(first, "w", encoding="utf-8") as handle:
                handle.write("uninitialized\n")
            with open(second, "w", encoding="utf-8") as handle:
                handle.write("A1B2C3D4E5F60718293A4B5C6D7E8F90\n")
            with mock.patch.object(hwid, "_LINUX_MACHINE_ID_PATHS", (first, second)):
                self.assertEqual(hwid_from_machine_id(hwid.read_machine_id("linux")), VECTORS["hwid"]["examples"][1]["hwid"])
            with open(first, "w", encoding="utf-8") as handle:
                handle.write(" UNINITIALIZED \n")
            with mock.patch.object(hwid, "_LINUX_MACHINE_ID_PATHS", (first,)):
                with self.assertRaises(HardwareIdError):
                    hwid.read_machine_id("linux")

    def test_macos_ioreg_parsing(self):
        output = (
            b'+-o J314sAP  <class IOPlatformExpertDevice>\n'
            b'    "IOPlatformSerialNumber" = "XYZ"\n'
            b'    "IOPlatformUUID" = "F3E2D1C0-B9A8-7766-5544-332211009988"\n'
        )
        completed = mock.Mock(returncode=0, stdout=output)
        with mock.patch.object(hwid.os.path, "isfile", return_value=True), mock.patch.object(
            hwid.subprocess, "run", return_value=completed
        ) as run:
            raw = hwid.read_machine_id("darwin")
        self.assertEqual(hwid_from_machine_id(raw), VECTORS["hwid"]["examples"][2]["hwid"])
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
        self.assertFalse(kwargs.get("shell"))

    def test_unsupported_platform(self):
        with self.assertRaises(HardwareIdError):
            hwid.read_machine_id("sunos5")


class EncodingTests(unittest.TestCase):
    def test_b64url_decode_tolerates_missing_padding(self):
        for raw in (b"", b"a", b"ab", b"abc", b"abcd", bytes(range(256))):
            encoded = crypto.b64url_encode(raw)
            self.assertNotIn("=", encoded)
            self.assertEqual(crypto.b64url_decode(encoded), raw)
            padded = encoded + "=" * (-len(encoded) % 4)
            self.assertEqual(crypto.b64url_decode(padded), raw)

    def test_b64url_decode_is_strict(self):
        for bad in ("a", "ab+c", "ab/c", "ab c", "abc\n", "a===", "abcde", 5):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    crypto.b64url_decode(bad)  # type: ignore[arg-type]

    def test_nonce_format(self):
        nonces = {crypto.new_nonce() for _ in range(200)}
        self.assertEqual(len(nonces), 200)
        for nonce in nonces:
            self.assertRegex(nonce, re.compile(r"^[A-Za-z0-9_-]{43}$"))
            self.assertEqual(len(crypto.b64url_decode(nonce)), 32)


if __name__ == "__main__":
    unittest.main()
