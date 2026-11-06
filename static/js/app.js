// Inline handlers are blocked by our Content-Security-Policy, so behaviour lives here.

// Confirm dialogs for forms marked data-confirm.
document.addEventListener("submit", function (e) {
  var msg = e.target.dataset ? e.target.dataset.confirm : null;
  if (msg && !window.confirm(msg)) { e.preventDefault(); }
});

// Light / dark toggle.
document.addEventListener("click", function (e) {
  var btn = e.target.closest("[data-theme-toggle]");
  if (!btn) { return; }
  var root = document.documentElement;
  var next = root.getAttribute("data-bs-theme") === "light" ? "dark" : "light";
  root.setAttribute("data-bs-theme", next);
  try { localStorage.setItem("tv-theme", next); } catch (err) { /* ignore */ }
});
