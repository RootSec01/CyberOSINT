window.Globe = (canvas, servers, alarmed, still) => {
  const ctx = canvas.getContext("2d");
  const RAD = Math.PI / 180;
  const HUB = { lat: 24.7, lon: 46.7 };
  const COLORS = {
    brand: [62, 230, 193],
    match: [62, 230, 160],
    subset: [90, 169, 255],
    unknown: [154, 166, 180],
    deviation: [255, 59, 78],
    current: [255, 255, 255],
  };

  const raw = window.RAQEEB_LAND || [];
  const count = raw.length / 2;
  const cosLat = new Float32Array(count);
  const sinLat = new Float32Array(count);
  const lons = new Float32Array(count);
  for (let i = 0; i < count; i++) {
    const lat = (raw[i * 2] / 10) * RAD;
    cosLat[i] = Math.cos(lat);
    sinLat[i] = Math.sin(lat);
    lons[i] = raw[i * 2 + 1] / 10;
  }

  const stars = Array.from({ length: 180 }, () => [Math.random(), Math.random(), Math.random() * 1.2 + .2, Math.random() * Math.PI * 2]);

  let width = 0;
  let height = 0;
  let dpr = 1;
  let spin = -HUB.lon;
  let tilt = 20;
  let target = null;
  let targetTilt = 20;
  let current = -1;
  const states = servers.map(() => null);
  const strikes = [];
  let started = performance.now();

  const resize = () => {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    const box = canvas.getBoundingClientRect();
    width = Math.max(1, Math.round(box.width * dpr));
    height = Math.max(1, Math.round(box.height * dpr));
    canvas.width = width;
    canvas.height = height;
  };
  new ResizeObserver(resize).observe(canvas);
  resize();

  const vector = (lat, lon) => {
    const la = lat * RAD;
    const lo = lon * RAD;
    return [Math.cos(la) * Math.sin(lo), Math.sin(la), Math.cos(la) * Math.cos(lo)];
  };

  const turn = ([x, y, z]) => {
    const lo = spin * RAD;
    const ti = tilt * RAD;
    const x1 = x * Math.cos(lo) + z * Math.sin(lo);
    const z1 = -x * Math.sin(lo) + z * Math.cos(lo);
    const y2 = y * Math.cos(ti) - z1 * Math.sin(ti);
    const z2 = y * Math.sin(ti) + z1 * Math.cos(ti);
    return [x1, y2, z2];
  };

  const rgba = (c, a) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;

  const slerp = (a, b, t) => {
    const dot = Math.min(1, Math.max(-1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]));
    const omega = Math.acos(dot);
    if (omega < 1e-4) return a;
    const s = Math.sin(omega);
    const wa = Math.sin((1 - t) * omega) / s;
    const wb = Math.sin(t * omega) / s;
    return [a[0] * wa + b[0] * wb, a[1] * wa + b[1] * wb, a[2] * wa + b[2] * wb];
  };

  const arcPoint = (a, b, t, lift) => {
    const p = slerp(a, b, t);
    const h = 1 + lift * Math.sin(Math.PI * t);
    return turn([p[0] * h, p[1] * h, p[2] * h]);
  };

  const hidden = (p) => p[2] < 0 && p[0] * p[0] + p[1] * p[1] < 1;

  const drawArc = (cx, cy, R, from, color, alpha, now, live) => {
    const a = vector(from.lat, from.lon);
    const b = vector(HUB.lat, HUB.lon);
    const span = Math.acos(Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]));
    const lift = .12 + span * .12;
    const steps = 64;
    ctx.lineWidth = (live ? 2.4 : 1.4) * dpr;
    ctx.lineCap = "round";
    for (let i = 0; i < steps; i++) {
      const p = arcPoint(a, b, i / steps, lift);
      const q = arcPoint(a, b, (i + 1) / steps, lift);
      if (hidden(p) || hidden(q)) continue;
      ctx.strokeStyle = rgba(color, alpha * (.35 + .65 * Math.sin(Math.PI * i / steps)));
      ctx.beginPath();
      ctx.moveTo(cx + p[0] * R, cy - p[1] * R);
      ctx.lineTo(cx + q[0] * R, cy - q[1] * R);
      ctx.stroke();
    }
    if (!live) return;
    for (let k = 0; k < 3; k++) {
      const t = ((now / 1400) + k / 3) % 1;
      const p = arcPoint(a, b, t, lift);
      if (hidden(p)) continue;
      const x = cx + p[0] * R;
      const y = cy - p[1] * R;
      const glow = ctx.createRadialGradient(x, y, 0, x, y, 10 * dpr);
      glow.addColorStop(0, rgba([255, 255, 255], .95));
      glow.addColorStop(.3, rgba(color, .8));
      glow.addColorStop(1, rgba(color, 0));
      ctx.fillStyle = glow;
      ctx.beginPath();
      ctx.arc(x, y, 10 * dpr, 0, Math.PI * 2);
      ctx.fill();
    }
  };

  const drawMarker = (cx, cy, R, place, color, now, label, pulse) => {
    const p = turn(vector(place.lat, place.lon));
    if (p[2] < -.05) return;
    const x = cx + p[0] * R;
    const y = cy - p[1] * R;
    const fade = Math.min(1, .35 + p[2]);
    if (pulse) {
      for (let k = 0; k < 2; k++) {
        const t = ((now / 1300) + k / 2) % 1;
        ctx.strokeStyle = rgba(color, (1 - t) * .8 * fade);
        ctx.lineWidth = 2 * dpr;
        ctx.beginPath();
        ctx.arc(x, y, (6 + t * 26) * dpr, 0, Math.PI * 2);
        ctx.stroke();
      }
    }
    const glow = ctx.createRadialGradient(x, y, 0, x, y, 16 * dpr);
    glow.addColorStop(0, rgba(color, .9 * fade));
    glow.addColorStop(1, rgba(color, 0));
    ctx.fillStyle = glow;
    ctx.beginPath();
    ctx.arc(x, y, 16 * dpr, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = rgba(color, fade);
    ctx.beginPath();
    ctx.arc(x, y, 4.2 * dpr, 0, Math.PI * 2);
    ctx.fill();
    if (label && p[2] > .15) {
      ctx.font = `700 ${12 * dpr}px ui-monospace, Menlo, Consolas, monospace`;
      const w = ctx.measureText(label).width;
      const lx = x + 12 * dpr;
      const ly = y - 12 * dpr;
      ctx.fillStyle = "rgba(5,8,12,.78)";
      ctx.strokeStyle = rgba(color, .6 * fade);
      ctx.lineWidth = 1 * dpr;
      ctx.beginPath();
      ctx.roundRect(lx - 6 * dpr, ly - 13 * dpr, w + 12 * dpr, 19 * dpr, 6 * dpr);
      ctx.fill();
      ctx.stroke();
      ctx.fillStyle = rgba(color, fade);
      ctx.fillText(label, lx, ly + 1 * dpr);
    }
  };

  const drawHub = (cx, cy, R, now) => {
    const p = turn(vector(HUB.lat, HUB.lon));
    if (p[2] < 0) return;
    const x = cx + p[0] * R;
    const y = cy - p[1] * R;
    const s = 7 * dpr;
    const beat = 1 + .15 * Math.sin(now / 300);
    ctx.save();
    ctx.translate(x, y);
    ctx.rotate(Math.PI / 4);
    ctx.scale(beat, beat);
    ctx.fillStyle = rgba(COLORS.brand, 1);
    ctx.shadowColor = rgba(COLORS.brand, 1);
    ctx.shadowBlur = 20 * dpr;
    ctx.fillRect(-s, -s, s * 2, s * 2);
    ctx.restore();
    ctx.font = `700 ${12 * dpr}px ui-monospace, Menlo, Consolas, monospace`;
    ctx.fillStyle = rgba(COLORS.brand, 1);
    ctx.fillText("RAQEEB · RIYADH", x + 14 * dpr, y + 22 * dpr);
  };

  const frame = (now) => {
    const t = now - started;
    if (target !== null) {
      let d = ((target - spin + 540) % 360) - 180;
      spin += d * (still ? 1 : .045);
      tilt += (targetTilt - tilt) * (still ? 1 : .045);
    } else if (!still) {
      spin += .06;
      tilt += (20 - tilt) * .02;
    }

    ctx.clearRect(0, 0, width, height);
    const cx = width / 2;
    const cy = height / 2;
    const R = Math.min(width, height) * .43;
    const red = alarmed();
    const land = red ? COLORS.deviation : COLORS.brand;

    for (const [sx, sy, size, phase] of stars) {
      ctx.fillStyle = `rgba(200,230,255,${.25 + .35 * Math.sin(t / 900 + phase) ** 2})`;
      ctx.fillRect(sx * width, sy * height, size * dpr, size * dpr);
    }

    const halo = ctx.createRadialGradient(cx, cy, R * .9, cx, cy, R * 1.35);
    halo.addColorStop(0, rgba(land, red ? .45 : .3));
    halo.addColorStop(.4, rgba(land, .08));
    halo.addColorStop(1, rgba(land, 0));
    ctx.fillStyle = halo;
    ctx.beginPath();
    ctx.arc(cx, cy, R * 1.35, 0, Math.PI * 2);
    ctx.fill();

    const body = ctx.createRadialGradient(cx - R * .35, cy - R * .4, R * .1, cx, cy, R);
    body.addColorStop(0, red ? "#2a0a10" : "#0d2a2b");
    body.addColorStop(1, "#04070b");
    ctx.fillStyle = body;
    ctx.beginPath();
    ctx.arc(cx, cy, R, 0, Math.PI * 2);
    ctx.fill();

    const sweep = ((t / (current >= 0 ? 2200 : 6000)) * 360) % 360;
    const lo = spin * RAD;
    const ti = tilt * RAD;
    const cosLo = Math.cos(lo);
    const sinLo = Math.sin(lo);
    const cosTi = Math.cos(ti);
    const sinTi = Math.sin(ti);
    const dot = 1.7 * dpr;
    for (let i = 0; i < count; i++) {
      const lon = lons[i] * RAD;
      const x = cosLat[i] * Math.sin(lon);
      const y = sinLat[i];
      const z = cosLat[i] * Math.cos(lon);
      const x1 = x * cosLo + z * sinLo;
      const z1 = -x * sinLo + z * cosLo;
      const y2 = y * cosTi - z1 * sinTi;
      const z2 = y * sinTi + z1 * cosTi;
      if (z2 < 0) {
        ctx.fillStyle = rgba(land, .05);
        ctx.fillRect(cx + x1 * R, cy - y2 * R, dot * .7, dot * .7);
        continue;
      }
      const screenLon = (Math.atan2(x1, z2) / RAD + 360) % 360;
      const near = Math.abs(((screenLon - sweep + 540) % 360) - 180);
      const lit = near < 8 ? 1 - near / 8 : 0;
      const a = .25 + .65 * z2;
      ctx.fillStyle = lit ? `rgba(${Math.round(land[0] + (255 - land[0]) * lit)},${Math.round(land[1] + (255 - land[1]) * lit)},${Math.round(land[2] + (255 - land[2]) * lit)},${Math.min(1, a + lit * .4)})` : rgba(land, a);
      const size = dot * (.7 + .5 * z2 + lit * .6);
      ctx.fillRect(cx + x1 * R - size / 2, cy - y2 * R - size / 2, size, size);
    }

    const rim = ctx.createRadialGradient(cx, cy, R * .82, cx, cy, R * 1.01);
    rim.addColorStop(0, rgba(land, 0));
    rim.addColorStop(1, rgba(land, .35));
    ctx.fillStyle = rim;
    ctx.beginPath();
    ctx.arc(cx, cy, R, 0, Math.PI * 2);
    ctx.fill();

    ctx.save();
    ctx.translate(cx, cy);
    ctx.rotate(-.35);
    ctx.strokeStyle = rgba(land, .22);
    ctx.lineWidth = 1 * dpr;
    ctx.setLineDash([4 * dpr, 7 * dpr]);
    ctx.beginPath();
    ctx.ellipse(0, 0, R * 1.22, R * .34, 0, 0, Math.PI * 2);
    ctx.stroke();
    ctx.setLineDash([]);
    const orbit = t / 2600;
    const ox = Math.cos(orbit) * R * 1.22;
    const oy = Math.sin(orbit) * R * .34;
    if (Math.sin(orbit) > -.2 || Math.abs(ox) > R) {
      ctx.fillStyle = rgba([255, 255, 255], .95);
      ctx.shadowColor = rgba(land, 1);
      ctx.shadowBlur = 14 * dpr;
      ctx.beginPath();
      ctx.arc(ox, oy, 3.2 * dpr, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;
    }
    ctx.restore();

    servers.forEach((server, i) => {
      const state = states[i];
      if (i === current) drawArc(cx, cy, R, server, red ? COLORS.deviation : COLORS.brand, .95, t, true);
      else if (state) drawArc(cx, cy, R, server, COLORS[state], .45, t, false);
    });

    drawHub(cx, cy, R, t);

    servers.forEach((server, i) => {
      const state = i === current ? (red ? "deviation" : "current") : states[i];
      const color = state ? COLORS[state] : [110, 125, 140];
      drawMarker(cx, cy, R, server, color, t, state ? server.name : null, i === current || state === "deviation");
    });

    for (let k = strikes.length - 1; k >= 0; k--) {
      const hit = strikes[k];
      const age = (now - hit.at) / 1800;
      if (age > 1) { strikes.splice(k, 1); continue; }
      const p = turn(vector(hit.lat, hit.lon));
      if (p[2] < 0) continue;
      const x = cx + p[0] * R;
      const y = cy - p[1] * R;
      for (let ring = 0; ring < 3; ring++) {
        const a = Math.max(0, age - ring * .12);
        ctx.strokeStyle = rgba(COLORS.deviation, (1 - a) * .9);
        ctx.lineWidth = (4 - ring) * dpr;
        ctx.beginPath();
        ctx.arc(x, y, a * R * .9, 0, Math.PI * 2);
        ctx.stroke();
      }
    }

    requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);

  return {
    reset() {
      states.fill(null);
      current = -1;
      target = null;
    },
    focus(i) {
      current = i;
      target = -servers[i].lon;
      targetTilt = Math.max(-40, Math.min(40, servers[i].lat * .7));
    },
    settle(i, verdict) {
      states[i] = verdict;
      if (current === i) current = -1;
      target = null;
    },
    strike(i) {
      strikes.push({ lat: servers[i].lat, lon: servers[i].lon, at: performance.now() });
    },
  };
};
