"""Windows digital-signature (Authenticode) check via PowerShell.

Windows-only and best-effort: it adds the publisher's real name when present.
It is never the whole verdict. Anywhere else, or on any failure, it reports
"unknown" instead of failing the check.
"""
import base64
import json
import subprocess
import sys

SIGNABLE = (".exe", ".msi", ".msix", ".dll", ".sys", ".cat", ".ps1", ".bat", ".com")


def is_signable(path):
    return path.lower().endswith(SIGNABLE)


def check_signature(path, _runner=None):
    """Return {"status": ..., "signer": ...} with plain-language status."""
    if sys.platform != "win32":
        return {"status": "not_windows", "signer": None,
                "detail": "Signature check only runs on Windows."}
    if not is_signable(path):
        return {"status": "not_signable", "signer": None,
                "detail": "This kind of file does not carry a Windows signature."}
    ps = (
        "$s = Get-AuthenticodeSignature -LiteralPath $args[0]; "
        "$o = [PSCustomObject]@{ Status = $s.Status.ToString(); "
        "Signer = $(if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { $null }) }; "
        "$o | ConvertTo-Json -Compress"
    )
    enc = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc, path]
    run = _runner or subprocess.run
    try:
        out = run(cmd, capture_output=True, text=True, timeout=30)
    except Exception as exc:
        return {"status": "unknown", "signer": None, "detail": f"Signature check failed to run: {exc}"}
    if out.returncode != 0 or not (out.stdout or "").strip():
        return {"status": "unknown", "signer": None, "detail": "Windows did not answer the signature check."}
    try:
        data = json.loads(out.stdout.strip().splitlines()[-1])
    except ValueError:
        return {"status": "unknown", "signer": None, "detail": "Windows' answer was not readable."}
    status = str(data.get("Status") or "unknown")
    signer = data.get("Signer")
    detail = {
        "Valid": "Windows confirms the signature is valid.",
        "HashMismatch": "The file was changed after signing. Do not trust it.",
        "NotSigned": "The file is not signed.",
        "UnknownError": "Windows could not check the signature.",
        "NotTrusted": "The signature is not from a trusted publisher.",
        "Incompatible": "Windows cannot read this signature.",
    }.get(status, f"Windows reports the signature status: {status}.")
    return {"status": status, "signer": signer, "detail": detail}
