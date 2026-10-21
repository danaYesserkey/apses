"""Shop API — каталог и корзина с проверкой JWT от Keycloak."""

import os

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

# --- Настройки берутся из переменных окружения, не из кода ---
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
REALM = os.getenv("KEYCLOAK_REALM", "shop")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "iOS-app")

ISSUER = f"{KEYCLOAK_URL}/realms/{REALM}"
JWKS_URL = f"{ISSUER}/protocol/openid-connect/certs"

app = FastAPI(title="Shop API")
bearer = HTTPBearer(auto_error=False)
jwks_client = jwt.PyJWKClient(JWKS_URL, cache_keys=True)

# --- Данные в памяти (для мидтерма; база — позже) ---
CATALOG = {
    1: {"id": 1, "name": "Apple juice", "price": 2.99},
    2: {"id": 2, "name": "Orange juice", "price": 3.49},
    3: {"id": 3, "name": "Banana juice", "price": 3.99},
}
CARTS: dict[str, dict[int, int]] = {}  # user_id -> {product_id: qty}


class CartItem(BaseModel):
    product_id: int = Field(gt=0)
    qty: int = Field(gt=0, le=100)


class Product(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    price: float = Field(gt=0)


# --- Проверка токена ---
def current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")
    try:
        key = jwks_client.get_signing_key_from_jwt(creds.credentials).key
        claims = jwt.decode(
            creds.credentials,
            key,
            algorithms=["RS256"],
            issuer=ISSUER,
            options={"verify_aud": False},  # aud у Keycloak = "account"; проверяем azp ниже
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Invalid token: {exc}") from exc
    if claims.get("azp") != CLIENT_ID:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token issued for another client")
    return claims


def require_role(role: str):
    def checker(claims: dict = Depends(current_user)) -> dict:
        roles = claims.get("realm_access", {}).get("roles", [])
        if role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Role '{role}' required")
        return claims

    return checker


# --- Каталог: читать может любой, менять — только admin ---
@app.get("/catalog")
def list_catalog():
    return list(CATALOG.values())


@app.post("/admin/catalog", status_code=201)
def add_product(product: Product, claims: dict = Depends(require_role("admin"))):
    new_id = max(CATALOG) + 1
    CATALOG[new_id] = {"id": new_id, **product.model_dump()}
    return CATALOG[new_id]


# --- Корзина: только своя, только для customer ---
@app.get("/cart")
def get_cart(claims: dict = Depends(require_role("customer"))):
    cart = CARTS.get(claims["sub"], {})
    items = [{**CATALOG[pid], "qty": qty} for pid, qty in cart.items() if pid in CATALOG]
    total = round(sum(i["price"] * i["qty"] for i in items), 2)  # цена считается на сервере
    return {"items": items, "total": total}


@app.post("/cart/items", status_code=201)
def add_to_cart(item: CartItem, claims: dict = Depends(require_role("customer"))):
    if item.product_id not in CATALOG:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Product not found")
    cart = CARTS.setdefault(claims["sub"], {})
    cart[item.product_id] = cart.get(item.product_id, 0) + item.qty
    return {"ok": True}


@app.get("/me")
def me(claims: dict = Depends(current_user)):
    return {"user": claims.get("preferred_username"), "roles": claims.get("realm_access", {}).get("roles", [])}
