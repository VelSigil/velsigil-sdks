"""Classify every vector in sdks/test-vectors.json (SPEC 10.7)."""

from __future__ import annotations

import copy
import hashlib
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
from velsigil_client import crypto, hwid  # noqa: E402

VECTORS = ms.VECTORS


def classify_envelope(verifier, vector, hwid=None):
    """``hwid``: the device the request was sent for (default: the vector's ``hwid``, if any)."""
    try:
        payload = open_envelope(
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
        payload = verify_lease(verifier, vector["token"], vector["productId"], vector["hwid"], vector["now"])
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
        self.assertEqual(key_id_for(VECTORS["keys"]["publicKey"]), VECTORS["keys"]["keyId"])
        self.assertEqual(Ed25519Verifier(VECTORS["keys"]["publicKey"]).key_id, VECTORS["keys"]["keyId"])

    def test_public_key_parsing(self):
        key = VECTORS["keys"]["publicKey"]
        # missing padding and surrounding whitespace are tolerated
        Ed25519Verifier(key.rstrip("="))
        Ed25519Verifier("  " + key + "\n")
        for bad in ("", "not base64!", "AAAA", key[:-8], key + "AAAA", None):
            with self.subTest(bad=bad):
                with self.assertRaises(ConfigurationError):
                    Ed25519Verifier(bad)  # type: ignore[arg-type]

    def test_unknown_backend_rejected(self):
        with self.assertRaises(ConfigurationError):
            Ed25519Verifier(VECTORS["keys"]["publicKey"], backend="openssl-cli")

    def test_backend_fallback_and_missing_backend(self):
        key = VECTORS["keys"]["publicKey"]

        def unavailable(raw):
            raise ImportError("simulated missing package")

        with mock.patch.object(crypto, "_cryptography_verifier", unavailable):
            with self.assertRaises(CryptoBackendError):
                Ed25519Verifier(key, backend="cryptography")
            # "auto" falls through to PyNaCl; without it, construction fails closed.
            with mock.patch.object(crypto, "_nacl_verifier", unavailable):
                with self.assertRaises(CryptoBackendError):
                    Ed25519Verifier(key)
            with mock.patch.object(crypto, "_nacl_verifier", lambda raw: (lambda sig, msg: False)):
                verifier = Ed25519Verifier(key)
                self.assertEqual(verifier.backend, "nacl")
                self.assertEqual(classify_envelope(verifier, VECTORS["envelopes"][0])[0], "invalid_signature")


class EnvelopeVectorTests(unittest.TestCase):
    def test_every_envelope_vector(self):
        self.assertGreaterEqual(len(VECTORS["envelopes"]), 11)
        for backend in _backends():
            verifier = Ed25519Verifier(VECTORS["keys"]["publicKey"], backend=backend)
            for vector in VECTORS["envelopes"]:
                with self.subTest(backend=backend, vector=vector["name"]):
                    outcome, payload = classify_envelope(verifier, vector)
                    self.assertEqual(outcome, vector["expect"])
                    if outcome == "valid":
                        self.assertEqual(payload, vector["payload"])

    def test_device_binding_vectors_are_authentic(self):
        # LIC-4: these envelopes carry valid signatures for the right nonce and product; only the
        # binding of their lease / activation.hwidHash to the requesting hwid rejects them.
        verifier = Ed25519Verifier(VECTORS["keys"]["publicKey"])
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
        # Proves the mock server signs exactly like the real one.
        for vector in VECTORS["envelopes"]:
            if vector["expect"] != "valid":
                continue
            with self.subTest(vector=vector["name"]):
                self.assertEqual(ms.encode_payload(vector["payload"]), vector["envelope"]["data"])
                self.assertEqual(ms.sign_text(vector["envelope"]["data"]), vector["envelope"]["sig"])

    def test_kid_is_ignored_for_key_selection(self):
        verifier = Ed25519Verifier(VECTORS["keys"]["publicKey"])
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
        verifier = Ed25519Verifier(VECTORS["keys"]["publicKey"])
        vector = copy.deepcopy(VECTORS["envelopes"][0])
        vector["envelope"]["sig"] += "=="
        self.assertEqual(classify_envelope(verifier, vector)[0], "valid")

    def test_structurally_broken_envelopes(self):
        verifier = Ed25519Verifier(VECTORS["keys"]["publicKey"])
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
                    open_envelope(verifier, envelope, good["requestNonce"], good["productId"], good["requestType"])
                self.assertEqual(ctx.exception.reason, expected)

    def test_signed_but_unparseable_payload_is_malformed(self):
        verifier = Ed25519Verifier(VECTORS["keys"]["publicKey"])
        for data in (ms.b64url(b"not json"), ms.b64url(b"[1,2]"), ms.b64url(b'{"v":2}'), "@@@@"):
            with self.subTest(data=data):
                envelope = {"data": data, "sig": ms.sign_text(data)}
                with self.assertRaises(EnvelopeError) as ctx:
                    open_envelope(verifier, envelope, "n", ms.PRODUCT_ID, "validate")
                self.assertEqual(ctx.exception.reason, "malformed")

    def test_type_mismatch(self):
        verifier = Ed25519Verifier(VECTORS["keys"]["publicKey"])
        vector = VECTORS["envelopes"][0]
        with self.assertRaises(EnvelopeError) as ctx:
            open_envelope(verifier, vector["envelope"], vector["requestNonce"], vector["productId"], "deactivate")
        self.assertEqual(ctx.exception.reason, "type_mismatch")
        payload = open_envelope(verifier, vector["envelope"], vector["requestNonce"], vector["productId"], "validate")
        self.assertTrue(payload["ok"])

    def test_type_mismatch_vector_is_authentic(self):
        # SDK-1: a signed update-check answer (ok: true, no license involved) for this request's nonce
        # and product must not pass as the answer to a (device-bound) validate request.
        verifier = Ed25519Verifier(VECTORS["keys"]["publicKey"])
        vector = {v["name"]: v for v in VECTORS["envelopes"]}["type_mismatch"]
        self.assertEqual(vector["requestType"], "validate")
        self.assertEqual((vector["payload"]["type"], vector["payload"]["ok"]), ("update_check", True))
        self.assertEqual(classify_envelope(verifier, vector)[0], "type_mismatch")
        payload = open_envelope(
            verifier, vector["envelope"], vector["requestNonce"], vector["productId"], "update_check", vector["hwid"]
        )
        self.assertEqual(payload, vector["payload"])
        self.assertEqual(ms.encode_payload(vector["payload"]), vector["envelope"]["data"])

    def test_expected_type_is_required(self):
        verifier = Ed25519Verifier(VECTORS["keys"]["publicKey"])
        vector = {v["name"]: v for v in VECTORS["envelopes"]}["type_mismatch"]
        args = (verifier, vector["envelope"], vector["requestNonce"], vector["productId"])
        with self.assertRaises(TypeError):
            open_envelope(*args)  # type: ignore[call-arg]
        for missing in (None, "", 5):
            with self.subTest(expected_type=missing):
                with self.assertRaises(ValueError):
                    open_envelope(*args, missing)  # type: ignore[arg-type]
                with self.assertRaises(ValueError):
                    open_envelope(*args, expected_type=missing, expected_hwid=vector["hwid"])  # type: ignore[arg-type]


class LeaseVectorTests(unittest.TestCase):
    def test_every_lease_vector(self):
        self.assertGreaterEqual(len(VECTORS["leases"]), 8)
        for backend in _backends():
            verifier = Ed25519Verifier(VECTORS["keys"]["publicKey"], backend=backend)
            for vector in VECTORS["leases"]:
                with self.subTest(backend=backend, vector=vector["name"]):
                    outcome, payload = classify_lease(verifier, vector)
                    self.assertEqual(outcome, vector["expect"])
                    if outcome == "valid":
                        self.assertEqual(payload, vector["payload"])

    def test_expiry_boundary(self):
        verifier = Ed25519Verifier(VECTORS["keys"]["publicKey"])
        vector = VECTORS["leases"][0]
        exp = vector["payload"]["exp"]
        self.assertEqual(classify_lease(verifier, dict(vector, now=exp - 1))[0], "valid")
        self.assertEqual(classify_lease(verifier, dict(vector, now=exp))[0], "expired")

    def test_lease_signature_padding_is_tolerated(self):
        verifier = Ed25519Verifier(VECTORS["keys"]["publicKey"])
        vector = dict(VECTORS["leases"][0])
        vector["token"] += "=="
        self.assertEqual(classify_lease(verifier, vector)[0], "valid")

    def test_malformed_tokens(self):
        verifier = Ed25519Verifier(VECTORS["keys"]["publicKey"])
        base = VECTORS["leases"][0]
        body, sig = base["token"].split(".")
        for token in ("", ".", body + ".", "." + sig, body + "." + sig + ".x", None, 42):
            with self.subTest(token=token):
                self.assertEqual(classify_lease(verifier, dict(base, token=token))[0], "malformed")

    def test_signed_lease_without_required_claims_is_malformed(self):
        verifier = Ed25519Verifier(VECTORS["keys"]["publicKey"])
        body = ms.encode_payload({"v": 1, "typ": "lease", "productId": ms.PRODUCT_ID})
        token = body + "." + ms.sign_text(body)
        self.assertEqual(
            classify_lease(verifier, {"token": token, "productId": ms.PRODUCT_ID, "hwid": ms.TEST_HWID, "now": 0})[0],
            "malformed",
        )


class FreeTrialVectorTests(unittest.TestCase):
    """SPEC 9.7: the optional signed ``trial`` field, ``trial_already_used`` and unknown fields."""

    def setUp(self):
        self.verifier = Ed25519Verifier(VECTORS["keys"]["publicKey"])
        self.by_name = {v["name"]: v for v in VECTORS["envelopes"]}
        self.leases = {v["name"]: v for v in VECTORS["leases"]}

    def test_trial_license_flag(self):
        outcome, payload = classify_envelope(self.verifier, self.by_name["validate_ok_trial"])
        self.assertEqual(outcome, "valid")
        self.assertTrue(LicenseInfo.from_payload(payload["license"], granted=True).is_trial)
        # Paid licenses carry no trial field at all.
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
        """SPEC 9.7: ``license.trialRef`` on convertible trials (also license_expired); the "Buy now" link."""
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
        # Without the field (paid licenses, older servers): None, and links stay unchanged.
        plain = _result_from_payload(classify_envelope(self.verifier, self.by_name["validate_ok_trial"])[1])
        self.assertIsNone(plain.trial_ref)
        self.assertEqual(plain.with_trial_ref("https://shop.example.com/buy"), "https://shop.example.com/buy")
        # The link builder.
        ref = self.by_name["validate_ok_trial_ref"]["payload"]["license"]["trialRef"]
        self.assertEqual(TRIAL_REF_PARAM, "velsigil_trial")
        self.assertEqual(with_trial_ref("https://shop.example.com/buy?plan=pro#top", ref), "https://shop.example.com/buy?plan=pro&velsigil_trial=" + ref + "#top")
        self.assertEqual(with_trial_ref("https://shop.example.com/buy?", ref), "https://shop.example.com/buy?velsigil_trial=" + ref)
        self.assertEqual(with_trial_ref("https://buy.stripe.com/test_abc", ref), "https://buy.stripe.com/test_abc?client_reference_id=" + ref)
        self.assertEqual(with_trial_ref("mailto:sales@example.com", ref), "mailto:sales@example.com")
        self.assertEqual(with_trial_ref("https://shop.example.com/buy", "has space"), "https://shop.example.com/buy")
        # Malformed values make the payload malformed.
        for bad in (42, "", "has space", "x" * 201, "ünicode"):
            with self.subTest(bad=bad):
                license_obj = dict(self.by_name["validate_ok_trial"]["payload"]["license"], trialRef=bad)
                with self.assertRaises(ValueError):
                    LicenseInfo.from_payload(license_obj)


class InAppTrialVectorTests(unittest.TestCase):
    """SPEC 9.7 "In-app trials": answers of type ``trial`` and the key of a started trial."""

    def setUp(self):
        self.verifier = Ed25519Verifier(VECTORS["keys"]["publicKey"])
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
        except HardwareIdError as exc:  # e.g. minimal containers without machine-id
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

    # Final sweep F-SDK-3: systemd's placeholder is not a machine id (the same rule in every SDK).
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
