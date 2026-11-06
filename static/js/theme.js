// Runs in <head> before first paint so the saved theme never flashes.
(function () {
  var theme = "dark";
  try {
    var saved = localStorage.getItem("tv-theme");
    if (saved === "light" || saved === "dark") { theme = saved; }
  } catch (e) { /* storage unavailable: keep default */ }
  document.documentElement.setAttribute("data-bs-theme", theme);
})();
