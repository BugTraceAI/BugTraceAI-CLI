"""Attack-surface predicates — decide whether a probed URL is real attack surface.

# PURE — this module performs NO I/O. The caller issues the requests and passes the
observations in, so every decision here is unit-testable offline against fixtures.

WHY THIS EXISTS
---------------
Endpoint existence cannot be read off an HTTP status code, in either direction:

  * A site that redirects HTTP to HTTPS answers 301 for EVERY path, including paths that
    do not exist. A rule like `status < 404` therefore accepts a randomly generated
    nonsense path — i.e. it accepts everything.
  * A site with a soft-404 answers HTTP 200 with a body that says "not found". A rule
    like `status == 200` accepts those too.
  * A WAF/CDN interstitial (challenge page, 429, 403) answers uniformly for every path,
    real or not.

Matching words in the body ("not found", "page does not exist") fails just as badly: it
is a signature list, so it breaks on non-English targets, on SPAs that never say it, and
on CDN interstitials that say something else entirely.

The signal that DOES generalise is differential. Ask the same origin for a path that is
guaranteed not to exist, and keep only the responses that differ from it. That works in
any language, on any status code, behind any CDN, because the target itself defines what
"nothing here" looks like.

Two refinements make the comparison honest:

  1. Many "nothing here" pages echo the requested path back into the body, so raw body
     length tracks path length and a long path looks "different" purely because it is
     long. Trying to subtract the echo by searching for the path fails — targets render
     it in forms the scanner cannot enumerate (without the leading slash, percent-encoded,
     HTML-escaped, JSON-escaped, split across attributes). Measured on a live target, a
     404 page echoed the path twice, in a form a literal search missed entirely.

     So the echo is MEASURED instead of guessed. Three control paths of deliberately
     different lengths reveal how many body bytes each path byte adds, whatever the
     encoding, and that slope is subtracted analytically. On the same live target the
     relationship was exactly linear (slope 2.0 across both intervals).

  2. Some targets jitter (nonces, timestamps, A/B tests) or start rate-limiting mid-scan,
     making any model meaningless. The third control doubles as a held-out point: if the
     fitted line does not predict it, the model is rejected and the caller FAILS CLOSED.
     Guessing endpoints is a bonus, never the core of a scan, so discarding the bonus
     costs far less than admitting phantoms.

KNOWN LIMIT: the slope is fitted on flat control paths. A target that echoes only part of
a path (say the last segment) may be predicted imperfectly for deeper probe paths. The
tolerance absorbs small errors, and the failure direction is a missed guess, never a
fabricated finding.
"""

from typing import List, NamedTuple, Optional, Sequence
from urllib.parse import urlparse, urlunparse

# Byte tolerance when comparing predicted and observed body lengths. Matches the SPA-shell
# guard already used by the Broken Access Control check, so both comparisons behave alike.
DEFAULT_LENGTH_TOLERANCE = 64


class ProbeObservation(NamedTuple):
    """What the caller observed for one request. `path` is the path that was requested."""

    status: int
    body: str
    path: str


class ControlModel(NamedTuple):
    """A linear model of what this origin returns for paths that do not exist.

    `slope` is body bytes per path byte — i.e. how many times, in effect, the target
    echoes the requested path back into its "nothing here" page.
    """

    status: int
    base_length: int
    base_path_length: int
    slope: float


def build_control_model(
    short: ProbeObservation,
    middle: ProbeObservation,
    long: ProbeObservation,
    tolerance: int = DEFAULT_LENGTH_TOLERANCE,
) -> Optional[ControlModel]:
    """
    # PURE
    Fit AND validate the origin's "nothing here" response from three nonexistent paths.

    The two extremes give the slope; the middle one is held out to test it. Returns None —
    meaning "this target cannot be modelled, do not guess" — when the statuses disagree or
    when the fitted line fails to predict the held-out point, which is what jitter, A/B
    tests and rate limiting kicking in mid-scan all look like.
    """
    if not (short.status == middle.status == long.status):
        return None
    path_span = len(long.path) - len(short.path)
    if path_span <= 0:
        return None
    slope = (len(long.body) - len(short.body)) / path_span
    predicted_middle = len(short.body) + slope * (len(middle.path) - len(short.path))
    if abs(len(middle.body) - predicted_middle) > tolerance:
        return None
    return ControlModel(short.status, len(short.body), len(short.path), slope)


def predicted_length(model: ControlModel, path: str) -> float:
    """
    # PURE
    Body length this origin would return for `path` if nothing were there.
    """
    return model.base_length + model.slope * (len(path) - model.base_path_length)


def differs_from_control(
    probe: ProbeObservation,
    model: ControlModel,
    tolerance: int = DEFAULT_LENGTH_TOLERANCE,
) -> bool:
    """
    # PURE
    True when `probe` looks like real attack surface rather than the origin's catch-all.

    A different status is decisive on its own: an endpoint answering 401/403/302 where the
    control answers 404 IS interesting surface, and that falls out of the comparison
    without enumerating which codes are "good". Otherwise the body must diverge from what
    the model predicts for a path of that length by more than the tolerance.
    """
    if probe.status != model.status:
        return True
    return abs(len(probe.body) - predicted_length(model, probe.path)) > tolerance


def names_a_resource(entry: str) -> bool:
    """
    # PURE
    True when a wordlist entry names a RESOURCE rather than a pre-baked attack.

    An endpoint wordlist may guess *where* something lives; it must never ship the
    parameters or payloads to send there. Entries like `health?cmd=id` or
    `admin/email-preview?template={{7*7}}` are not discovery — they are one target's
    attack surface hardcoded into the scanner, and they get requested verbatim against
    every unrelated site. Parameters must come from observed forms, links, API schemas,
    JavaScript call sites or live responses.
    """
    return "?" not in entry and "=" not in entry


def drop_insecure_duplicate_origins(urls: Sequence[str]) -> List[str]:
    """
    # PURE
    Remove plain-HTTP URLs for any host that is also reachable over HTTPS.

    Recon commonly keeps both `http://host` and `https://host`. The HTTP one is worthless
    — it is the same site — but it is actively harmful: every probe sent to it is answered
    by the HTTP-to-HTTPS redirect rather than by the application, so the whole origin
    becomes a source of confident-looking noise. Keeping only the secure origin also stops
    the scan doing every piece of work twice.
    """
    secure_hosts = {
        urlparse(url).netloc for url in urls if urlparse(url).scheme == "https"
    }
    kept = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.scheme == "http" and parsed.netloc in secure_hosts:
            continue
        kept.append(url)
    return kept


def upgrade_scheme_to_https(url: str) -> str:
    """
    # PURE
    Return `url` with an https scheme. Used to derive the secure twin of an HTTP URL.
    """
    parsed = urlparse(url)
    if parsed.scheme != "http":
        return url
    return urlunparse(parsed._replace(scheme="https"))
