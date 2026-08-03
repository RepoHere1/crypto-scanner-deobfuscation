"""Kalshi API client with RSA-PSS request signing.

Authentication uses a Kalshi API key pair:
- KALSHI_API_KEY_ID: the public key identifier
- KALSHI_PRIVATE_KEY_PATH: path to the PEM-encoded RSA private key

Requests are signed with RSA-PSS SHA-256 over {timestamp_ms}{method}{path}.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from base64 import b64encode
from typing import Any
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

logger = logging.getLogger(__name__)

# Kalshi API base — note this differs from the old trading-api.kalshi.com
API_BASE = "https://api.elections.kalshi.com/trade-api/v2"
DEMO_BASE = "https://external-api.demo.kalshi.co/trade-api/v2"
# V2 order endpoint uses a different base URL
ORDER_BASE = "https://external-api.kalshi.com/trade-api/v2"


class KalshiError(Exception):
    """Raised for Kalshi API errors."""
    def __init__(self, status: int, message: str, body: dict | None = None):
        self.status = status
        self.message = message
        self.body = body or {}
        super().__init__(f"[{status}] {message}")


class AuthError(KalshiError):
    """401/403 — bad credentials or insufficient permissions."""


class InsufficientFunds(KalshiError):
    """Order rejected due to insufficient balance."""


class KalshiClient:
    """Authenticated HTTP client for the Kalshi Trading API v2.

    Usage:
        client = KalshiClient.from_env()
        markets = client.get_markets(series_ticker="KXBTCD")
        order = client.place_order(ticker="...", side="yes", count=10, price=45)
    """

    def __init__(
        self,
        api_key_id: str | None = None,
        private_key_path: str | None = None,
        api_base: str | None = None,
        demo: bool = False,
        timeout: int = 15,
    ):
        self.api_key_id = api_key_id or os.environ.get("KALSHI_API_KEY_ID", "")
        key_path = private_key_path or os.environ.get("KALSHI_PRIVATE_KEY_PATH", "")

        if not self.api_key_id:
            raise ValueError(
                "KALSHI_API_KEY_ID required. Set env var or pass api_key_id."
            )
        if not key_path:
            raise ValueError(
                "KALSHI_PRIVATE_KEY_PATH required. Set env var or pass private_key_path."
            )

        self.api_base = api_base or (DEMO_BASE if demo else API_BASE)
        self._api_path = urlparse(self.api_base).path
        self.timeout = timeout

        # Load the RSA private key
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
            if not isinstance(key, RSAPrivateKey):
                raise TypeError(f"Expected RSA private key, got {type(key).__name__}")
            self._private_key: RSAPrivateKey = key

    @classmethod
    def from_env(cls, **kwargs: Any) -> "KalshiClient":
        """Create client from environment variables."""
        return cls(**kwargs)

    # --- Auth ---

    def _sign(self, method: str, path: str) -> tuple[str, str]:
        """Create RSA-PSS signature for a request.

        Returns (timestamp_ms, base64_signature).
        """
        timestamp = str(int(time.time() * 1000))
        message = f"{timestamp}{method}{path}"
        signature = self._private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )
        return timestamp, b64encode(signature).decode()

    def _headers(self, method: str, endpoint: str) -> dict[str, str]:
        """Build authenticated request headers."""
        path_only = urlparse(endpoint).path
        full_path = f"{self._api_path}{path_only}"
        ts, sig = self._sign(method, full_path)
        return {
            "Content-Type": "application/json",
            "KALSHI-ACCESS-KEY": self.api_key_id,
            "KALSHI-ACCESS-SIGNATURE": sig,
            "KALSHI-ACCESS-TIMESTAMP": ts,
        }

    # --- HTTP ---

    def _request(self, method: str, endpoint: str, body: dict | None = None,
                 base: str | None = None) -> dict:
        """Make an authenticated request and return parsed JSON."""
        base_url = base or self.api_base
        url = endpoint if endpoint.startswith("http") else f"{base_url}{endpoint}"
        data_bytes = json.dumps(body).encode() if body else None
        headers = self._headers(method, endpoint)

        logger.debug("%s %s", method, endpoint)
        req = Request(url, data=data_bytes, headers=headers, method=method)

        try:
            with urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 204 or resp.length == 0:
                    return {}
                return json.loads(resp.read().decode())
        except HTTPError as e:
            return self._handle_error(e)

    def _handle_error(self, error: HTTPError) -> dict:
        """Parse error response and raise appropriate exception."""
        try:
            body = json.loads(error.read().decode())
        except Exception:
            body = {}

        inner = body.get("error", {}) if isinstance(body.get("error"), dict) else {}
        message = inner.get("message") or body.get("message", str(error))
        code = inner.get("code") or body.get("code", "")

        if error.code in (401, 403):
            raise AuthError(error.code, message, body)
        if code == "insufficient_funds":
            raise InsufficientFunds(error.code, message, body)
        raise KalshiError(error.code, message, body)

    def get(self, endpoint: str) -> dict:
        """GET request."""
        return self._request("GET", endpoint)

    def post(self, endpoint: str, body: dict) -> dict:
        """POST request."""
        return self._request("POST", endpoint, body)

    # --- Markets ---

    def get_markets(
        self,
        series_ticker: str | None = None,
        status: str = "open",
        limit: int = 100,
    ) -> list[dict]:
        """Fetch markets, optionally filtered by series."""
        params: dict[str, str | int] = {"status": status, "limit": limit}
        if series_ticker:
            params["series_ticker"] = series_ticker
        qs = urlencode(params)
        data = self.get(f"/markets?{qs}")
        return data.get("markets", [])

    def get_balance(self) -> dict:
        """Get account balance."""
        return self.get("/portfolio/balance")

    def place_order(
        self,
        ticker: str,
        side: str,
        count: int,
        price_cents: int,
        client_order_id: str | None = None,
    ) -> dict:
        """Place a binary option order via V2 endpoint.

        Args:
            ticker: Market ticker (e.g. KXBTCD-26AUG0117-T73249.99)
            side: "yes" (buy) or "no" (sell) — translated to bid/ask for V2
            count: Number of contracts
            price_cents: Price in cents (0-100, where 100 = $1.00)
            client_order_id: Idempotency key (auto-generated if omitted)
        """
        cid = client_order_id or str(uuid.uuid4())
        # V2 uses "bid"/"ask" instead of "yes"/"no"
        v2_side = "bid" if side.lower() == "yes" else "ask"
        # V2 price is a dollar string like "0.70", count is a string
        price_dollars = f"{price_cents / 100:.2f}"
        body = {
            "ticker": ticker,
            "client_order_id": cid,
            "side": v2_side,
            "count": str(count),
            "price": price_dollars,
            "time_in_force": "good_till_canceled",
            "self_trade_prevention_type": "taker_at_cross",
            "post_only": False,
            "cancel_order_on_pause": False,
            "reduce_only": False,
            "subaccount": 0,
            "exchange_index": 0,
        }
        return self._request("POST", "/portfolio/events/orders", body)
