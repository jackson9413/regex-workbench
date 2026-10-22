const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));
const esc = s => (s == null ? "" : String(s).replace(/[&<>"]/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])));

let SAMPLES = [];
let CURRENT = null;

function flags() {
  return $$(".flag").filter(c => c.checked).map(c => c.value).join("");
}

async function post(url, body) {
  const r = await fetch(url, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  return r.json();
}

// ------------------------------------------------------------------ analyze
async function analyze() {
  const pattern = $("#pattern").value;
  const res = await post("/api/analyze", { pattern, flags: flags() });
  const errBox = $("#error");

  if (res.error) {
    errBox.classList.remove("hidden");
    errBox.innerHTML = "<b>" + esc(res.error_kind === "flags" ? "Flag problem" : "This pattern will not compile")
      + "</b><br>" + esc(res.error)
      + (res.repair ? "<br><br><b>How to fix:</b> " + esc(res.repair) : "");
    $("#score-head").classList.add("hidden");
    $$(".tabpane").forEach(p => p.addClass?.("hidden"));
    return;
  }
  errBox.classList.add("hidden");
  CURRENT = res;
  renderScore(res);
  renderTokens(res);
  renderCaptures(res);
  renderRedos(res);
  renderMatrix(res);
}

// ------------------------------------------------------------------ render
function renderScore(r) {
  $("#score-head").classList.remove("hidden");
  $("#score-num").textContent = r.score;
  const v = $("#verdict");
  v.textContent = r.verdict.replace(/_/g, " ");
  v.className = "verdict " + r.verdict;
  $("#verdict-blurb").textContent = r.verdict_blurb;
  $("#axes").innerHTML = Object.entries(r.axes).map(([k, v2]) =>
    '<div class="axis"><b>' + esc(k) + '</b><span class="v">' + v2 + '</span>' +
    '<div class="bar"><i style="width:' + v2 + '%"></i></div></div>').join("");
  const badge = $("#redos-badge");
  if (r.redos.length) {
    badge.classList.remove("hidden");
    badge.textContent = r.redos.length;
  } else badge.classList.add("hidden");
}

function renderTokens(r) {
  const rows = r.explanation.map(e =>
    "<tr class='k-" + esc(e.kind) + "'><td class='pos'>" + e.pos + "</td><td class='tok'>"
    + esc(e.shown || "(empty)") + "</td><td>" + esc(e.note) + "</td></tr>").join("");
  $("#tokens").innerHTML = "<tr><th>pos</th><th>token</th><th>what it does</th></tr>" + rows;
}

function renderCaptures(r) {
  $("#captures").innerHTML = r.captures.length
    ? r.captures.map((c, i) =>
      '<div class="cap"><b>' + esc(c.name || ("group " + c.index)) + "</b> "
      + (c.name ? "#" + c.index : "") + " " + esc(c.source.slice(0, 40)) + "</div>").join("")
    : '<span class="note">No capture groups - this pattern only tells you yes or no.</span>';
}

function renderRedos(r) {
  if (!r.redos.length) {
    $("#redos-list").innerHTML =
      '<div class="finding"><h3>No backtracking bombs found</h3><p>Static analysis found no nested unbounded '
      + 'quantifiers, no quantifier that can match empty, and no ambiguous alternation. That said, this is a '
      + 'structural check, not a proof: a pattern can still be slow on huge inputs if it is doing a lot of work.</p></div>';
    return;
  }
  const timing = {};
  (r.timing || []).forEach(t => timing[t.kind] = t);
  $("#redos-list").innerHTML = r.redos.map(f => {
    const t = timing[f.kind];
    let measured = "";
    if (t) {
      measured = "<div class='probe probe-" + esc(t.probe || "none") + "'><b>"
        + (t.probe === "not_reproduced" ? "probe: not reproduced here" : "probe: " + esc(t.probe))
        + "</b><br>" + esc(t.probe_note || "") + "</div>";
    }
    return '<div class="finding ' + esc(f.severity) + '">'
      + '<span class="sev">' + esc(f.severity) + '</span>'
      + "<h3>" + esc(f.title) + "</h3>"
      + '<div class="snippet">' + esc(f.snippet) + "</div>"
      + "<p>" + esc(f.why) + "</p>"
      + '<div class="fix"><b>Fix:</b> ' + esc(f.fix) + "</div>"
      + (f.attack ? '<div class="attack">attack string <code>' + esc(f.attack) + "</code> &rarr; " + measured + "</div>" : "")
      + "</div>";
  }).join("");
}

function renderMatrix(r) {
  $("#matrix").innerHTML = r.matrix.map(e => {
    const bad = e.blocked.length
      ? "<b>not supported:</b> " + esc(e.blocked.join(", "))
      : "<b>differs subtly:</b> " + esc(e.different.join(", ") || "nothing detected");
    const notes = e.notes.map(n => "<li>" + esc(n) + "</li>").join("");
    return '<div class="eng"><div class="top"><span class="nm">' + esc(e.name) + "</span>"
      + '<span class="ver">' + esc(e.version) + "</span>"
      + '<span class="st ' + esc(e.status) + '">' + esc(e.status) + "</span>"
      + '<span class="ver">flags: ' + esc(e.flags.join(" ") || "(none)") + "</span></div>"
      + "<ul><li>" + bad + "</li>" + notes + "</ul></div>";
  }).join("");
}

// ------------------------------------------------------------------ tests
async function runTests() {
  const lines = $("#cases").value.split("\n").map(s => s.trim()).filter(Boolean);
  const res = await post("/api/run-tests", { pattern: $("#pattern").value, flags: flags(), cases: lines });
  const msg = $("#test-msg");
  if (res.error) { msg.textContent = res.error; return; }
  const pass = res.tests.filter(t => t.passed).length;
  msg.innerHTML = '<span class="pill ' + (pass === res.tests.length ? "pass" : "fail") + '">'
    + pass + " / " + res.tests.length + " passed</span>";
  $("#test-results").innerHTML = res.tests.map(t => {
    const groups = t.groups && t.groups.length
      ? "<div class='meta'>" + t.groups.map(g => "#" + g.index + "=" + JSON.stringify(g.value)).join("  ") + "</div>"
      : "";
    const named = t.named && Object.keys(t.named).length
      ? "<div class='meta'>" + Object.entries(t.named).map(([k, v]) => k + "=" + JSON.stringify(v)).join("  ") + "</div>"
      : "";
    return '<div class="case ' + (t.passed ? "pass" : "fail") + '">'
      + '<span class="pill ' + (t.passed ? "pass" : "fail") + '">' + (t.passed ? "PASS" : "FAIL") + "</span> "
      + '<span class="in">' + esc(t.input) + "</span>"
      + "<span class='pill'>expected " + esc(t.expect) + ", got " + esc(t.got) + "</span>"
      + (t.span ? "<div class='meta'>matched " + esc(JSON.stringify(t.span.text)) +
        " at [" + t.span.start + "," + t.span.end + ")</div>" : "")
      + groups + named + "</div>";
  }).join("");
}

// ------------------------------------------------------------------ saved
async function saveSession() {
  if (!CURRENT) return;
  const payload = {
    score: CURRENT.score, verdict: CURRENT.verdict, axes: CURRENT.axes,
    verdict_blurb: CURRENT.verdict_blurb, redos: CURRENT.redos, matrix: CURRENT.matrix,
    features: CURRENT.features
  };
  const r = await post("/api/sessions", {
    pattern: $("#pattern").value, flags: flags(), score: CURRENT.score,
    verdict: CURRENT.verdict, note: $("#note").value, payload
  });
  $("#save-msg").textContent = "saved as #" + r.id;
  loadSaved();
}

async function loadSaved() {
  const r = await fetch("/api/sessions").then(x => x.json());
  $("#saved-list").innerHTML = r.sessions.length ? r.sessions.map(s => {
    const stars = [1, 2, 3, 4, 5].map(n =>
      "<a data-id='" + s.id + "' data-n='" + n + "' href='#'>" + (n <= s.rating ? "<b>★</b>" : "★") + "</a>").join("");
    return '<div class="saved"><div class="pat">' + esc(s.pattern)
      + (s.flags ? "  /" + esc(s.flags) : "") + "</div>"
      + '<div class="meta">#' + s.id + " - " + esc(s.created_at) + " - score " + s.score
      + " (" + esc(s.verdict) + ")</div>"
      + '<div class="stars" data-id="' + s.id + '">' + stars + "</div>"
      + (s.note ? '<div class="meta">' + esc(s.note) + "</div>" : "")
      + '<div style="margin-top:8px"><a href="/api/export/' + s.id + '?fmt=md">export md</a>'
      + '<a href="/api/export/' + s.id + '?fmt=json">export json</a>'
      + '<a href="#" class="load" data-id="' + s.id + '">load</a></div></div>";
  }).join("") : '<div class="note">Nothing saved yet.</div>';
}

// ------------------------------------------------------------------ wiring
document.querySelectorAll(".tabs button").forEach(b => b.addEventListener("click", () => {
  document.querySelectorAll(".tabs button").forEach(x => x.classList.remove("active"));
  b.classList.add("active");
  $$(".tabpane").forEach(p => p.classList.add("hidden"));
  $("#tab-" + b.dataset.tab).classList.remove("hidden");
}));

$("#analyze").addEventListener("click", analyze);
$("#pattern").addEventListener("keydown", e => { if (e.key === "Enter") analyze(); });
$("#runtests").addEventListener("click", runTests);
$("#save").addEventListener("click", saveSession);
$("#reload-saved").addEventListener("click", loadSaved);

$("#samples").addEventListener("change", e => {
  const s = SAMPLES.find(x => x.name === e.target.value);
  if (!s) return;
  $("#pattern").value = s.pattern;
  $$(".flag").forEach(c => { c.checked = s.flags.includes(c.value); });
  $("#sample-note").textContent = s.note;
  analyze();
});

$("#saved-list").addEventListener("click", async e => {
  const t = e.target;
  if (t.dataset && t.dataset.id && t.dataset.n) {
    const r = await fetch("/api/sessions/" + t.dataset.id, {
      method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rating: parseInt(t.dataset.n, 10) })
    }).then(x => x.json());
    if (r.session) { await fetch("/api/sessions/" + t.dataset.id, {
      method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ note: r.session.note || "" })
    }); loadSaved(); }
    e.preventDefault();
    return;
  }
  if (t.classList && t.classList.contains("load")) {
    e.preventDefault();
    const r = await fetch("/api/sessions/" + t.dataset.id).then(x => x.json());
    if (r.session) {
      $("#pattern").value = r.session.pattern;
      $$(".flag").forEach(c => { c.checked = (r.session.flags || "").includes(c.value); });
      $("#note").value = r.session.note || "";
      analyze();
    }
  }
});

(async function boot() {
  const s = await fetch("/api/samples").then(x => x.json());
  SAMPLES = s.samples;
  $("#samples").innerHTML = '<option value="">load a sample...</option>' +
    SAMPLES.map(x => '<option>' + esc(x.name) + "</option>").join("");
  const h = await fetch("/api/health").then(x => x.json());
  $("#health").textContent = h.engines + " engines checked.";
  loadSaved();
  $("#pattern").value = SAMPLES[1].pattern;
  $("#sample-note").textContent = SAMPLES[1].note;
  analyze();
})();
