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

  const radar = document.getElementById("radar");
  const readout = document.querySelector(".readout");
  const detail = document.getElementById("detail");
  const chips = [...radar.querySelectorAll(".chip")];
  let timers = [];

  const show = (chip) => {
    chips.forEach((c) => c.classList.toggle("picked", c === chip));
    detail.dataset.show = chip.classList.contains("bad") ? "bad" : "ok";
    detail.querySelectorAll(".tool-name").forEach((el) => { el.textContent = chip.dataset.tool; });
  };

  const scan = () => {
    timers.forEach(clearTimeout);
    timers = [];
    chips.forEach((c) => c.classList.remove("picked"));
    detail.dataset.show = "hint";
    if (still) {
      readout.dataset.state = "done";
      return;
    }
    readout.dataset.state = "scan";
    radar.classList.add("scanning");
    chips.forEach((c) => c.classList.add("pending"));
    chips.forEach((chip, i) => {
      timers.push(setTimeout(() => chip.classList.remove("pending"), 700 + i * 650));
    });
    timers.push(setTimeout(() => {
      radar.classList.remove("scanning");
      readout.dataset.state = "done";
      const bad = chips.find((c) => c.classList.contains("bad"));
      if (bad) show(bad);
    }, 700 + chips.length * 650));
  };

  chips.forEach((chip) => chip.addEventListener("click", () => {
    if (chip.classList.contains("pending")) return;
    show(chip);
  }));
  document.getElementById("scan").addEventListener("click", scan);

  if (!still) {
    radar.addEventListener("pointermove", (e) => {
      const box = radar.getBoundingClientRect();
      const x = (e.clientX - box.left) / box.width - 0.5;
      const y = (e.clientY - box.top) / box.height - 0.5;
      radar.style.setProperty("--tx", `${(-y * 8).toFixed(2)}deg`);
      radar.style.setProperty("--ty", `${(x * 8).toFixed(2)}deg`);
    });
    radar.addEventListener("pointerleave", () => {
      radar.style.setProperty("--tx", "0deg");
      radar.style.setProperty("--ty", "0deg");
    });
  }

  setTimeout(scan, 600);

  const dialog = document.getElementById("contact");
  const name = document.getElementById("contact-name");
  const avatar = document.getElementById("contact-avatar");
  const link = document.getElementById("contact-link");
  const handle = document.getElementById("contact-handle");

  document.querySelectorAll(".member").forEach((member) => member.addEventListener("click", () => {
    name.replaceChildren(...[...member.querySelector(".who").children].map((n) => n.cloneNode(true)));
    avatar.replaceChildren(...[...member.querySelector(".avatar").children].map((n) => n.cloneNode(true)));
    avatar.className = `avatar big ${member.dataset.tone}`;
    link.href = member.dataset.link;
    handle.textContent = member.dataset.link.replace(/^https:\/\/www\./, "").replace(/\/$/, "");
    dialog.showModal();
  }));
  document.getElementById("contact-close").addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (e) => { if (e.target === dialog) dialog.close(); });

  const STEPS = [
    { at: "hero", ar: "رقيب يحمي وكلاء الذكاء الاصطناعي من الأدوات التي تم العبث بها.", en: "Raqeeb protects AI agents from tools that have been tampered with." },
    { at: "radar", ar: "شاهد الفحص: الأدوات الخضراء تطابق الأصل، والحمراء تغيّرت. اضغط على أي أداة لترى التفاصيل.", en: "Watch the scan: green tools match the original, the red one was changed. Tap any tool for details.", enter: scan },
    { at: "simple", ar: "الفكرة ببساطة: الوكيل يصدّق وصف الأداة، ورقيب يتأكد أن أحداً لم يعدّله.", en: "The idea in short: the agent believes a tool's description, and Raqeeb makes sure nobody edited it." },
    { at: "diff", ar: "هكذا يبدو الهجوم: جملة مخفية واحدة تكفي لسرقة مفتاح خاص.", en: "This is what an attack looks like: one hidden sentence is enough to steal a private key." },
    { at: "how", ar: "ثلاث خطوات: يقرأ الأدوات، ويطابقها مع الأصل، وينبّه عند أي تغيير.", en: "Three steps: read the tools, compare them with the original, and alert on any change." },
    { at: "results", ar: "نتائج مَقيسة: كشف 83.3% من الأوصاف المسمومة، دون أي إنذار كاذب على الأوصاف السليمة.", en: "Measured results: 83.3% of poisoned descriptions caught, with no false alarms on clean ones." },
    { at: "team", ar: "تعرّف على الفريق، واضغط على أي عضو للتواصل معه.", en: "Meet the team. Tap any member to get in touch." },
    { at: "closing", ar: "جرّب العرض الحي بنفسك، فهو يُطلق تنبيهات جديدة كل بضع دقائق.", en: "Try the live demo yourself. It raises new alerts every few minutes." },
  ];
  const STEP_MS = 7000;

  const welcome = document.getElementById("welcome");
  const spot = document.getElementById("spot");
  const tour = document.getElementById("tour");
  const tourAr = document.getElementById("tour-ar");
  const tourEn = document.getElementById("tour-en");
  const tourCount = document.getElementById("tour-count");
  const progress = document.getElementById("tour-progress");
  let step = -1;
  let advance = null;

  const target = () => document.querySelector(`[data-tour="${STEPS[step].at}"]`);

  const place = () => {
    if (step < 0) return;
    const box = target().getBoundingClientRect();
    const pad = 12;
    spot.style.setProperty("--x", `${box.left - pad}px`);
    spot.style.setProperty("--y", `${box.top - pad}px`);
    spot.style.setProperty("--w", `${box.width + pad * 2}px`);
    spot.style.setProperty("--h", `${box.height + pad * 2}px`);
    const below = innerHeight - Math.min(box.bottom, innerHeight);
    const above = Math.max(box.top, 0) - document.querySelector(".bar").offsetHeight;
    tour.classList.toggle("top", above > below);
  };

  const go = (n) => {
    clearTimeout(advance);
    if (n >= STEPS.length) { finish(); return; }
    step = Math.max(0, n);
    const s = STEPS[step];
    tourAr.textContent = s.ar;
    tourEn.textContent = s.en;
    tourCount.textContent = `${step + 1} / ${STEPS.length}`;
    const el = target();
    const tall = el.getBoundingClientRect().height > innerHeight * 0.6;
    el.scrollIntoView({ behavior: still ? "auto" : "smooth", block: tall ? "start" : "center", inline: "nearest" });
    if (s.enter) s.enter();
    progress.classList.remove("run");
    void progress.offsetWidth;
    progress.classList.add("run");
    advance = setTimeout(() => go(step + 1), STEP_MS);
  };

  const start = () => {
    stopShow();
    welcome.hidden = true;
    spot.hidden = false;
    tour.hidden = false;
    document.body.classList.add("touring");
    go(0);
  };

  const finish = () => {
    clearTimeout(advance);
    step = -1;
    spot.hidden = true;
    tour.hidden = true;
    document.body.classList.remove("touring");
  };


  welcome.querySelectorAll(".pick").forEach((b) => b.addEventListener("click", () => {
    apply(b.dataset.lang);
    try { localStorage.setItem("lang", b.dataset.lang); } catch {}
    start();
  }));
  document.getElementById("browse").addEventListener("click", () => { welcome.hidden = true; });
  document.getElementById("tour-next").addEventListener("click", () => go(step + 1));
  document.getElementById("tour-back").addEventListener("click", () => go(step - 1));
  document.getElementById("tour-end").addEventListener("click", finish);
  addEventListener("scroll", place, { passive: true });
  addEventListener("resize", place);
  setInterval(place, 250);

  const stops = [...document.querySelectorAll("[data-show]")];
  const button = document.getElementById("autoplay");
  const HOLD_MS = 6000;
  const IDLE_MS = 60000;
  let showing = false;
  let hold = null;
  let idle = null;

  const swap = (lang) => {
    if (still) { apply(lang); return; }
    document.body.classList.add("swapping");
    setTimeout(() => {
      apply(lang);
      document.body.classList.remove("swapping");
    }, 350);
  };

  const visit = (i, lang) => {
    if (!showing) return;
    const stop = stops[i % stops.length];
    if (lang !== root.lang) swap(lang);
    if (lang === "ar") {
      stop.scrollIntoView({ behavior: still ? "auto" : "smooth", block: "start" });
      if (stop.dataset.tour === "hero") scan();
    }
    hold = setTimeout(() => (lang === "ar" ? visit(i, "en") : visit(i + 1, "ar")), HOLD_MS);
  };

  function stopShow() {
    showing = false;
    clearTimeout(hold);
    document.body.classList.remove("showing", "swapping");
  }

  const playShow = () => {
    if (dialog.open) dialog.close();
    if (step >= 0) finish();
    welcome.hidden = true;
    showing = true;
    document.body.classList.add("showing");
    visit(0, "ar");
  };

  const wake = (e) => {
    if (e && e.target instanceof Element && e.target.closest("#autoplay")) return;
    if (showing) stopShow();
    clearTimeout(idle);
    idle = setTimeout(playShow, IDLE_MS);
  };

  button.addEventListener("click", () => {
    if (showing) { stopShow(); wake(); } else { playShow(); }
  });
  ["pointerdown", "keydown", "wheel", "touchstart"].forEach((type) => addEventListener(type, wake, { passive: true }));

  welcome.hidden = false;
  wake();

  const counters = document.querySelectorAll("[data-count]");
  if (still || !("IntersectionObserver" in window)) return;

  const count = (el) => {
    const target = parseFloat(el.dataset.count);
    const places = (el.dataset.count.split(".")[1] || "").length;
    const suffix = el.dataset.suffix || "";
    const start = performance.now();
    const tick = (now) => {
      const t = Math.min((now - start) / 1400, 1);
      el.textContent = (target * (1 - Math.pow(1 - t, 3))).toFixed(places) + suffix;
      if (t < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  };

  const seen = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      count(entry.target);
      seen.unobserve(entry.target);
    }
  }, { threshold: 0.6 });
  counters.forEach((el) => seen.observe(el));
})();
