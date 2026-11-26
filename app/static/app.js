// Front-end for the Vuln Shop home page. Uses textContent (not innerHTML) so the
// home page itself is safe; the intentional XSS lives on the product page.

async function loadProducts(q = "") {
  const list = document.getElementById("products");
  list.textContent = "";
  const res = await fetch(`/api/products?q=${encodeURIComponent(q)}`);
  const data = await res.json();
  if (!res.ok) {
    const li = document.createElement("li");
    li.textContent = `Error: ${data.detail}`;
    list.appendChild(li);
    return;
  }
  for (const p of data) {
    const li = document.createElement("li");
    const a = document.createElement("a");
    a.href = `/products/${p.id}`;
    a.textContent = `${p.name} - $${Number(p.price).toFixed(2)}`;
    li.appendChild(a);
    list.appendChild(li);
  }
}

document.getElementById("search").addEventListener("submit", (e) => {
  e.preventDefault();
  loadProducts(e.target.q.value);
});

document.getElementById("chat").addEventListener("submit", async (e) => {
  e.preventDefault();
  const log = document.getElementById("chatlog");
  const message = e.target.message.value;
  log.textContent += `You: ${message}\n`;
  e.target.message.value = "";
  const res = await fetch("/api/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  });
  const data = await res.json();
  log.textContent += `ShopBot: ${res.ok ? data.reply : data.detail}\n\n`;
});

loadProducts();
