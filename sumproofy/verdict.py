"""Combine the local fingerprint with the lookup result into one answer."""
import hmac

MATCH = "match"
MISMATCH = "mismatch"
NO_OFFICIAL = "no_official"


def compare(local_hash, lookup):
    """lookup is a LookupResult. Returns (verdict, explanation).

    Wording is bold only when the official fingerprint came from a strong
    source (a stored digest or a checksum file). A fingerprint scraped from
    a web page proves less, so the answer says exactly that.
    """
    if lookup.status == "found" and lookup.official_hash:
        weak = getattr(lookup, "source_kind", None) == "weak"
        if hmac.compare_digest(local_hash.lower(), lookup.official_hash.lower()):
            if weak:
                return MATCH, ("The file matches the fingerprint printed on that page. "
                               "That proves the download was not corrupted - it does not "
                               "prove the page itself is the maker's real site.")
            return MATCH, "This file is exactly what the maker published."
        if weak:
            return MISMATCH, ("The file does NOT match the fingerprint printed on that page. "
                              "Do not run or open it unless you can confirm the page and the "
                              "fingerprint really come from the maker.")
        return MISMATCH, "The file is NOT what the maker published. Do not run or open it."
    if lookup.status == "ambiguous":
        return NO_OFFICIAL, lookup.detail + " Compare by eye before trusting it."
    if lookup.status == "error":
        return NO_OFFICIAL, "The official fingerprint could not be fetched: " + lookup.detail
    return NO_OFFICIAL, (lookup.detail or "No official fingerprint was found.") + \
        " Compare the file's fingerprint by eye if you can find the official one."
