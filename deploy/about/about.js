(() => {
  const root = document.documentElement;
  const asked = new URLSearchParams(location.search).get("lang");
  let saved = null;
  try { saved = localStorage.getItem("lang"); } catch {}

  const apply = (lang) => {
    root.lang = lang;
    root.dir = lang === "ar" ? "rtl" : "ltr";
    document.title = lang === "ar" ? "عن رقيب · CyberOSINT" : "About Raqeeb · CyberOSINT";
  };

  const pick = (lang) => (lang === "ar" || lang === "en" ? lang : null);
  const browser = (navigator.language || "").startsWith("ar") ? "ar" : "en";
  apply(pick(asked) || pick(saved) || browser);

  document.getElementById("language").addEventListener("click", () => {
    const next = root.lang === "ar" ? "en" : "ar";
    apply(next);
    try { localStorage.setItem("lang", next); } catch {}
  });

  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const counters = document.querySelectorAll("[data-count]");
  if (still || !("IntersectionObserver" in window)) return;

  const run = (el) => {
    const target = parseFloat(el.dataset.count);
    const places = (el.dataset.count.split(".")[1] || "").length;
    const suffix = el.dataset.suffix || "";
    const start = performance.now();
    const tick = (now) => {
      const t = Math.min((now - start) / 1400, 1);
      const eased = 1 - Math.pow(1 - t, 3);
      el.textContent = (target * eased).toFixed(places) + suffix;
      if (t < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  };

  const seen = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      run(entry.target);
      seen.unobserve(entry.target);
    }
  }, { threshold: 0.6 });
  counters.forEach((el) => seen.observe(el));
})();
