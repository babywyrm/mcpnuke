"""OAuth2/OIDC authentication support for mcpnuke."""

import base64
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from mcpnuke.core.constants import MCP_INIT_PARAMS


@dataclass
class AuthInfo:
    """Auth requirements discovered from an MCP server."""
    requires_auth: bool = False
    auth_type: str = ""
    realm: str = ""
    token_endpoint: str = ""
    issuer: str = ""
    www_authenticate: str = ""

    def summary(self) -> str:
        parts = []
        if self.auth_type:
            parts.append(f"type={self.auth_type}")
        if self.realm:
            parts.append(f"realm={self.realm}")
        if self.issuer:
            parts.append(f"issuer={self.issuer}")
        if self.token_endpoint:
            parts.append(f"token_endpoint={self.token_endpoint}")
        return ", ".join(parts) if parts else "unknown"


def parse_header_kv_pairs(values: list[str] | None) -> dict[str, str]:
    """Parse repeated KEY:VALUE CLI header flags into a dict."""
    headers: dict[str, str] = {}
    for raw in values or []:
        if ":" not in raw:
            raise ValueError(f"Invalid header format {raw!r}; expected KEY:VALUE")
        key, value = raw.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise ValueError(f"Invalid header format {raw!r}; key cannot be empty")
        headers[key] = value
    return headers


def decode_jwt_claims(token: str) -> dict[str, Any] | None:
    """Decode JWT payload claims without signature validation."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    payload = parts[1]
    padding = "=" * ((4 - len(payload) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload + padding)
        data = json.loads(decoded.decode("utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def summarize_jwt_claims(claims: dict[str, Any]) -> dict[str, Any]:
    """Return a minimal JWT claim summary useful for scan context."""
    keep = (
        "iss",
        "sub",
        "aud",
        "exp",
        "nbf",
        "iat",
        "jti",
        "azp",
        "scope",
        "scp",
        "client_id",
    )
    out: dict[str, Any] = {}
    for key in keep:
        if key in claims:
            out[key] = claims[key]
    return out


def summarize_introspection(introspection: dict[str, Any]) -> dict[str, Any]:
    """Return a minimal, stable summary from token introspection output."""
    keep = (
        "active",
        "scope",
        "client_id",
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "nbf",
        "token_type",
        "username",
    )
    out: dict[str, Any] = {}
    for key in keep:
        if key in introspection:
            out[key] = introspection[key]
    return out


def fetch_token_introspection(
    introspect_url: str,
    token: str,
    client_id: str | None = None,
    client_secret: str | None = None,
    timeout: float = 10.0,
    verify_tls: bool = False,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Call OAuth2 token introspection endpoint and return JSON body."""
    headers: dict[str, str] = {"Content-Type": "application/x-www-form-urlencoded"}
    if extra_headers:
        headers.update(extra_headers)
    data: dict[str, str] = {"token": token}
    if client_id:
        data["client_id"] = client_id
    if client_secret:
        data["client_secret"] = client_secret

    client = httpx.Client(verify=verify_tls, timeout=timeout)
    try:
        r = client.post(introspect_url, data=data, headers=headers)
        if r.status_code != 200:
            raise RuntimeError(
                f"Token introspection failed: HTTP {r.status_code} from {introspect_url}\n"
                f"Response: {r.text[:500]}"
            )
        body = r.json()
        if not isinstance(body, dict):
            raise RuntimeError("Token introspection response was not a JSON object")
        return body
    except httpx.HTTPError as e:
        raise RuntimeError(f"Token introspection error: {e}") from e
    finally:
        client.close()


def summarize_jwks(jwks: dict[str, Any]) -> dict[str, Any]:
    """Summarize JWKS key metadata for operator visibility."""
    keys = jwks.get("keys", [])
    if not isinstance(keys, list):
        keys = []
    kids: list[str] = []
    kty: set[str] = set()
    alg: set[str] = set()
    for key in keys:
        if not isinstance(key, dict):
            continue
        kid = key.get("kid")
        if isinstance(kid, str):
            kids.append(kid)
        if isinstance(key.get("kty"), str):
            kty.add(key["kty"])
        if isinstance(key.get("alg"), str):
            alg.add(key["alg"])
    return {
        "key_count": len(keys),
        "kids": sorted(kids)[:10],
        "kty": sorted(kty),
        "alg": sorted(alg),
    }


def fetch_jwks(
    jwks_url: str,
    timeout: float = 10.0,
    verify_tls: bool = False,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Fetch JWKS document and return parsed JSON."""
    headers: dict[str, str] = {}
    if extra_headers:
        headers.update(extra_headers)
    client = httpx.Client(verify=verify_tls, timeout=timeout)
    try:
        r = client.get(jwks_url, headers=headers)
        if r.status_code != 200:
            raise RuntimeError(
                f"JWKS fetch failed: HTTP {r.status_code} from {jwks_url}\n"
                f"Response: {r.text[:500]}"
            )
        body = r.json()
        if not isinstance(body, dict):
            raise RuntimeError("JWKS response was not a JSON object")
        return body
    except httpx.HTTPError as e:
        raise RuntimeError(f"JWKS fetch error: {e}") from e
    finally:
        client.close()


def detect_auth_requirements(
    url: str,
    timeout: float = 5.0,
    verify_tls: bool = False,
    extra_headers: dict[str, str] | None = None,
) -> AuthInfo:
    """Probe an MCP endpoint for authentication requirements.
    
    Sends an unauthenticated initialize and examines the response.
    If 401/403, parses WWW-Authenticate and tries OIDC discovery.
    """
    info = AuthInfo()
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.rstrip("/") or "/mcp"
    post_url = base + path

    base_headers: dict[str, str] = {"Content-Type": "application/json"}
    if extra_headers:
        base_headers.update(extra_headers)

    client = httpx.Client(verify=verify_tls, timeout=timeout, follow_redirects=True)
    try:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": MCP_INIT_PARAMS,
        }
        r = client.post(
            post_url,
            json=payload,
            headers=base_headers,
        )

        if r.status_code in (401, 403):
            info.requires_auth = True
            www_auth = r.headers.get("www-authenticate", "")
            info.www_authenticate = www_auth

            if www_auth.lower().startswith("bearer"):
                info.auth_type = "bearer"
                # Parse realm="..." from WWW-Authenticate: Bearer realm="..."
                import re
                realm_match = re.search(r'realm="([^"]+)"', www_auth, re.IGNORECASE)
                if realm_match:
                    info.realm = realm_match.group(1)
            elif www_auth.lower().startswith("basic"):
                info.auth_type = "basic"
            else:
                info.auth_type = "bearer"  # assume bearer for MCP

            # Check JSON body for auth hints
            try:
                body = r.json()
                err = body.get("error", {})
                if isinstance(err, dict):
                    msg = err.get("message", "")
                    if "bearer" in msg.lower() or "token" in msg.lower():
                        info.auth_type = "bearer"
            except Exception:
                pass

            # Try OIDC discovery if we have a realm URL
            if info.realm:
                _discover_oidc(client, info.realm, info)
            
            # Try common Keycloak patterns from the server URL
            if not info.token_endpoint:
                _try_keycloak_discovery(client, base, info)

        elif r.status_code in (200, 202):
            info.requires_auth = False
            # Check if tools/list requires auth even though initialize doesn't
            try:
                body = r.json()
                if "result" in body:
                    tr = client.post(
                        post_url,
                        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                        headers=base_headers,
                    )
                    if tr.status_code in (401, 403):
                        info.requires_auth = True
                        info.auth_type = "bearer"
                        www_auth = tr.headers.get("www-authenticate", "")
                        info.www_authenticate = www_auth
                        import re
                        realm_match = re.search(r'realm="([^"]+)"', www_auth, re.IGNORECASE)
                        if realm_match:
                            info.realm = realm_match.group(1)
                        if info.realm:
                            _discover_oidc(client, info.realm, info)
            except Exception:
                pass

    except Exception:
        pass
    finally:
        client.close()

    return info


def _discover_oidc(client: httpx.Client, issuer_url: str, info: AuthInfo):
    """Try to fetch OIDC configuration from an issuer URL."""
    issuer_url = issuer_url.rstrip("/")
    well_known = f"{issuer_url}/.well-known/openid-configuration"
    try:
        r = client.get(well_known, timeout=5)
        if r.status_code == 200:
            data = r.json()
            info.issuer = data.get("issuer", issuer_url)
            info.token_endpoint = data.get("token_endpoint", "")
    except Exception:
        pass


def _try_keycloak_discovery(client: httpx.Client, base: str, info: AuthInfo):
    """Try common Keycloak realm paths for OIDC discovery."""
    # Common patterns: /realms/{name}/.well-known/openid-configuration
    # Try to find realm name from existing info or common names
    realm_names = ["master"]
    if info.realm:
        parsed = urlparse(info.realm)
        path_parts = parsed.path.strip("/").split("/")
        if "realms" in path_parts:
            idx = path_parts.index("realms")
            if idx + 1 < len(path_parts):
                realm_names.insert(0, path_parts[idx + 1])

    for realm in realm_names:
        for keycloak_base in [base, f"{base}:8080"]:
            well_known = f"{keycloak_base}/realms/{realm}/.well-known/openid-configuration"
            try:
                r = client.get(well_known, timeout=3)
                if r.status_code == 200:
                    data = r.json()
                    info.issuer = data.get("issuer", "")
                    info.token_endpoint = data.get("token_endpoint", "")
                    if info.token_endpoint:
                        return
            except Exception:
                pass


def fetch_client_credentials_token(
    oidc_url: str,
    client_id: str,
    client_secret: str,
    timeout: float = 10.0,
    scope: str | None = None,
    verify_tls: bool = False,
    extra_headers: dict[str, str] | None = None,
) -> str:
    """Fetch an access token using OAuth2 client_credentials grant.
    
    Args:
        oidc_url: OIDC issuer URL (e.g. http://keycloak:8080/realms/warbird)
                  or direct token endpoint URL.
        client_id: OAuth2 client ID.
        client_secret: OAuth2 client secret.
    
    Returns:
        Access token string.
    
    Raises:
        RuntimeError on failure.
    """
    oidc_url = oidc_url.rstrip("/")
    
    # Determine token endpoint
    token_endpoint = ""
    if "/token" in oidc_url:
        # Direct token endpoint provided
        token_endpoint = oidc_url
    else:
        # Try OIDC discovery
        client = httpx.Client(verify=verify_tls, timeout=timeout)
        try:
            well_known = f"{oidc_url}/.well-known/openid-configuration"
            r = client.get(well_known)
            if r.status_code == 200:
                token_endpoint = r.json().get("token_endpoint", "")
        except Exception:
            pass
        finally:
            client.close()
        
        if not token_endpoint:
            # Fallback: assume standard path
            token_endpoint = f"{oidc_url}/protocol/openid-connect/token"

    data: dict[str, str] = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if scope:
        data["scope"] = scope

    headers: dict[str, str] = {"Content-Type": "application/x-www-form-urlencoded"}
    if extra_headers:
        headers.update(extra_headers)

    client = httpx.Client(verify=verify_tls, timeout=timeout)
    try:
        r = client.post(
            token_endpoint,
            data=data,
            headers=headers,
        )
        if r.status_code != 200:
            raise RuntimeError(
                f"Token fetch failed: HTTP {r.status_code} from {token_endpoint}\n"
                f"Response: {r.text[:500]}"
            )
        data = r.json()
        token = data.get("access_token")
        if not token:
            raise RuntimeError(f"No access_token in response: {json.dumps(data)[:500]}")
        return token
    except httpx.HTTPError as e:
        raise RuntimeError(f"Token fetch error: {e}") from e
    finally:
        client.close()


def resolve_auth_token(args) -> str | None:
    """Resolve the auth token from CLI args (direct token or OIDC client credentials)."""
    if getattr(args, "auth_token", None):
        return args.auth_token

    client_id = getattr(args, "client_id", None)
    client_secret = getattr(args, "client_secret", None)

    if not client_id or not client_secret:
        return None

    oidc_url = getattr(args, "oidc_url", None)
    verify_tls = bool(getattr(args, "tls_verify", False))
    scope = getattr(args, "oidc_scope", None)
    extra_headers = parse_header_kv_pairs(getattr(args, "header", None))
    if not oidc_url:
        # Try to auto-detect from the first target
        targets = getattr(args, "targets", None)
        if targets:
            info = detect_auth_requirements(
                targets[0],
                verify_tls=verify_tls,
                extra_headers=extra_headers,
            )
            if info.token_endpoint:
                # Extract issuer from token endpoint
                oidc_url = info.issuer or info.token_endpoint.rsplit("/protocol/", 1)[0]
        
        if not oidc_url:
            raise RuntimeError(
                "Cannot determine OIDC URL. Provide --oidc-url or ensure the target "
                "server advertises auth requirements."
            )

    return fetch_client_credentials_token(
        oidc_url,
        client_id,
        client_secret,
        scope=scope,
        verify_tls=verify_tls,
        extra_headers=extra_headers,
    )
