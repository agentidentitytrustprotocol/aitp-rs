#!/usr/bin/env python3
"""
Template for a Python conformance adapter.

A conformance adapter speaks NDJSON over stdio. Each stdin line is a request;
each stdout line is the corresponding response. See
docs/conformance.md for the full adapter protocol and op vocabulary.

This file is a template; replace the TODO bodies with calls into your
Python AITP implementation.
"""

import json
import sys
import traceback

# State held across the lifetime of the adapter process.
keypairs = {}
sessions = {}
_next_handle = 0


def handle_init(_params):
    return {
        "implementation": "aitp-py-template",
        "version": "0.0.0",
        "supported_ops": [
            "verify_tct",
            "verify_manifest",
            "verify_jcs",
            "compute_jwk_thumbprint",
            "generate_keypair",
            "issue_tct",
            "issue_manifest",
        ],
        "supported_features": ["oidc_identity", "pinned_key_identity"],
    }


def handle_verify_tct(params):
    # TODO: parse params["tct"], verify against params["expected_audience"]
    # using params["issuer_pubkey"] (hex 32 bytes), then return verified TCT
    # info or raise an exception with an AITP error code.
    raise NotImplementedError


def handle_generate_keypair(params):
    global _next_handle
    # TODO: generate Ed25519 keypair (optionally from params["seed"]),
    # store in keypairs dict, return handle and AID.
    _next_handle += 1
    handle = f"kp-{_next_handle}"
    keypairs[handle] = None  # store actual key here
    return {"handle": handle, "aid": "aid:pubkey:..."}


# Add more handlers as your implementation supports more operations.
OP_HANDLERS = {
    "init": handle_init,
    "verify_tct": handle_verify_tct,
    "generate_keypair": handle_generate_keypair,
}


def main():
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            req_id = request.get("id", "unknown")
            op = request.get("op", "")
            params = request.get("params", {})

            if op == "shutdown":
                print(json.dumps({"id": req_id, "ok": True}), flush=True)
                return

            handler = OP_HANDLERS.get(op)
            if handler is None:
                resp = {
                    "id": req_id,
                    "ok": False,
                    "error_code": "OP_NOT_SUPPORTED",
                    "message": f"unknown op: {op}",
                }
            else:
                try:
                    result = handler(params)
                    resp = {"id": req_id, "ok": True, "result": result}
                except NotImplementedError:
                    resp = {
                        "id": req_id,
                        "ok": False,
                        "error_code": "OP_NOT_SUPPORTED",
                        "message": f"op '{op}' not implemented in this template",
                    }
                except Exception as e:
                    resp = {
                        "id": req_id,
                        "ok": False,
                        "error_code": "INTERNAL_ERROR",
                        "message": str(e),
                    }
            print(json.dumps(resp), flush=True)
        except Exception:
            sys.stderr.write(f"adapter fatal: {traceback.format_exc()}\n")
            sys.stderr.flush()
            return


if __name__ == "__main__":
    main()
