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
})();
