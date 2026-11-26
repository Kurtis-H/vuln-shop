"""Vuln Shop - an intentionally vulnerable web shop for security testing practice.

Every vulnerability is tagged VULN-XX and has a secure counterpart selected by VULN_MODE.
LOCAL USE ONLY. Never deploy this to a public server.
"""

import html
import sqlite3
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import chatbot
from app.auth import create_token, current_user, verify_login
from app.config import Settings
from app.db import connect, init_db

STATIC_DIR = Path(__file__).parent / "static"


class LoginIn(BaseModel):
    username: str
    password: str


class ReviewIn(BaseModel):
    body: str = Field(min_length=1, max_length=2000)


class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=4000)


def create_app(settings: Settings | None = None, reset_db: bool = True, llm=None) -> FastAPI:
    settings = settings or Settings()
    init_db(settings.db_path, reset=reset_db)

    app = FastAPI(title=f"Vuln Shop ({settings.mode} mode)")
    app.state.settings = settings
    app.state.llm = llm or chatbot.build_llm(settings)

    def get_db():
        conn = connect(settings.db_path)
        try:
            yield conn
        finally:
            conn.close()

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        if not settings.is_vulnerable:
            # VULN-03 fix, layer 2: a Content-Security-Policy blocks inline scripts.
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
            )
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/health")
    def health():
        return {"status": "ok", "mode": settings.mode}

    @app.post("/api/login")
    def login(body: LoginIn, db: sqlite3.Connection = Depends(get_db)):
        user = verify_login(db, body.username, body.password)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid username or password")
        return {"token": create_token(user["id"], user["username"], settings.jwt_secret)}

    # VULN-01: SQL injection in product search.
    @app.get("/api/products")
    def search_products(q: str = "", db: sqlite3.Connection = Depends(get_db)):
        if settings.is_vulnerable:
            query = f"SELECT id, name, price FROM products WHERE hidden = 0 AND name LIKE '%{q}%'"
            try:
                rows = db.execute(query).fetchall()
            except sqlite3.Error as exc:
                # Leaking the raw database error is its own information-disclosure bug.
                raise HTTPException(status_code=500, detail=f"DB error: {exc}") from None
        else:
            rows = db.execute(
                "SELECT id, name, price FROM products WHERE hidden = 0 AND name LIKE ?",
                (f"%{q}%",),
            ).fetchall()
        return [dict(r) for r in rows]

    # VULN-02: IDOR - any logged-in user can read any order by changing the ID.
    @app.get("/api/orders/{order_id}")
    def get_order(
        order_id: int, user: dict = Depends(current_user), db: sqlite3.Connection = Depends(get_db)
    ):
        row = db.execute(
            "SELECT id, user_id, product_id, shipping_address FROM orders WHERE id = ?",
            (order_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Order not found")
        if not settings.is_vulnerable and row["user_id"] != user["id"]:
            # 404, not 403, so attackers can't tell which order IDs exist.
            raise HTTPException(status_code=404, detail="Order not found")
        return dict(row)

    @app.post("/api/products/{product_id}/reviews", status_code=201)
    def add_review(
        product_id: int,
        body: ReviewIn,
        user: dict = Depends(current_user),
        db: sqlite3.Connection = Depends(get_db),
    ):
        if db.execute("SELECT 1 FROM products WHERE id = ?", (product_id,)).fetchone() is None:
            raise HTTPException(status_code=404, detail="Product not found")
        with db:
            cur = db.execute(
                "INSERT INTO reviews (product_id, user_id, body) VALUES (?, ?, ?)",
                (product_id, user["id"], body.body),
            )
        return {"id": cur.lastrowid}

    # VULN-03: stored XSS - review text is rendered into HTML without escaping.
    @app.get("/products/{product_id}", response_class=HTMLResponse)
    def product_page(product_id: int, db: sqlite3.Connection = Depends(get_db)):
        product = db.execute(
            "SELECT id, name, price FROM products WHERE id = ? AND hidden = 0", (product_id,)
        ).fetchone()
        if product is None:
            raise HTTPException(status_code=404, detail="Product not found")
        reviews = db.execute(
            "SELECT r.body, u.username FROM reviews r JOIN users u ON u.id = r.user_id "
            "WHERE r.product_id = ? ORDER BY r.id",
            (product_id,),
        ).fetchall()

        def render(text: str) -> str:
            return text if settings.is_vulnerable else html.escape(text)

        items = "".join(
            f"<li><b>{render(r['username'])}</b>: {render(r['body'])}</li>" for r in reviews
        )
        return f"""<!doctype html>
<html lang="en"><head><title>{html.escape(product["name"])}</title></head>
<body>
  <p><a href="/">&larr; Back to shop</a></p>
  <h1>{html.escape(product["name"])}</h1>
  <p>${product["price"]:.2f}</p>
  <h2>Reviews</h2>
  <ul id="reviews">{items or "<li>No reviews yet.</li>"}</ul>
</body></html>"""

    # VULN-05: prompt injection / system prompt leakage (see app/chatbot.py).
    @app.post("/api/chat")
    def chat(body: ChatIn):
        try:
            reply = chatbot.answer(app.state.llm, body.message, settings.is_vulnerable)
        except Exception as exc:  # e.g. Ollama not running
            raise HTTPException(status_code=503, detail=f"Chatbot unavailable: {exc}") from None
        return {"reply": reply}

    @app.get("/", response_class=HTMLResponse)
    def index():
        return INDEX_HTML.replace("{{MODE}}", settings.mode)

    return app


INDEX_HTML = """<!doctype html>
<html lang="en"><head><title>Vuln Shop</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 760px; margin: 2rem auto; padding: 0 1rem; }
  .mode { display: inline-block; padding: 2px 8px; border-radius: 4px; background: #fde68a; }
  section { margin-top: 2rem; }
  #chatlog { white-space: pre-wrap; background: #f4f4f5; padding: 1rem; min-height: 4rem; }
</style></head>
<body>
  <h1>Vuln Shop <span class="mode">{{MODE}} mode</span></h1>
  <p>A deliberately vulnerable shop for security testing practice. Local use only.</p>
  <section>
    <h2>Products</h2>
    <form id="search"><input name="q" aria-label="Search products" placeholder="Search products"> <button>Search</button></form>
    <ul id="products"></ul>
  </section>
  <section>
    <h2>Support chat</h2>
    <form id="chat"><input name="message" size="60" aria-label="Message ShopBot" placeholder="Ask ShopBot..."> <button>Send</button></form>
    <div id="chatlog"></div>
  </section>
  <p>API docs: <a href="/docs">/docs</a></p>
<script src="/static/app.js"></script>
</body></html>"""
