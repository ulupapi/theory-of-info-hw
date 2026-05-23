import {
  DES_TABLES,
  bitsToAscii,
  bitsToBinary,
  bitsToHex,
  bruteForceEstimate,
  checkKeyParity,
  keyWarnings,
  normalizeBlock,
  runDes
} from "./des.js";

const $ = (id) => document.getElementById(id);
let currentMode = "encrypt";
let trace = null;

function boot() {
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => switchTab(tab.dataset.tab));
  });
  $("runBtn").addEventListener("click", run);
  $("vectorBtn").addEventListener("click", loadVector);
  $("weakBtn").addEventListener("click", loadWeakKey);
  $("roundRange").addEventListener("input", renderRound);
  $("prevRound").addEventListener("click", () => moveRound(-1));
  $("nextRound").addEventListener("click", () => moveRound(1));
  $("inputMode").addEventListener("change", updatePlaceholders);
  $("keyMode").addEventListener("change", updatePlaceholders);
  $("bruteForce").textContent = bruteForceEstimate().label;
  updatePlaceholders();
  run();
}

function switchTab(mode) {
  currentMode = mode === "decrypt" ? "decrypt" : "encrypt";
  document.querySelectorAll(".tab").forEach(tab => tab.classList.toggle("active", tab.dataset.tab === mode));
  $("modeBadge").textContent = currentMode === "encrypt" ? "ENC" : "DEC";
  $("dataLabel").textContent = currentMode === "encrypt" ? "Открытый текст" : "Шифротекст";
  $("resultTitle").textContent = currentMode === "encrypt" ? "Результат шифрования" : "Результат дешифрования";
  if (mode === "learn") {
    currentMode = "encrypt";
    $("modeBadge").textContent = "STEP";
  }
  run();
}

function updatePlaceholders() {
  const inputMode = $("inputMode").value;
  $("dataInput").placeholder = inputMode === "hex" ? "0123456789ABCDEF" : inputMode === "bin" ? "00000001 ..." : "OpenAI!!";
  $("keyInput").placeholder = $("keyMode").value === "hex" ? "133457799BBCDFF1" : "8 байт / 64 бита";
}

function loadVector() {
  $("inputMode").value = "hex";
  $("keyMode").value = "hex";
  $("dataInput").value = currentMode === "decrypt" ? "85E813540F0AB405" : "0123456789ABCDEF";
  $("keyInput").value = "133457799BBCDFF1";
  run();
}

function loadWeakKey() {
  $("keyMode").value = "hex";
  $("keyInput").value = "0000000000000000";
  run();
}

function run() {
  const dataBits = normalizeBlock($("dataInput").value, $("inputMode").value);
  const keyBits = normalizeBlock($("keyInput").value, $("keyMode").value);
  trace = runDes(dataBits, keyBits, currentMode === "decrypt");
  $("outHex").textContent = trace.outputHex;
  $("outBin").textContent = trace.outputBinary;
  $("outAscii").textContent = trace.outputAscii || "(непечатаемые байты)";
  $("outIp").textContent = bitsToHex(trace.ip);
  renderKeyStatus(keyBits);
  renderSubkeys();
  $("roundRange").value = "1";
  renderRound();
}

function renderKeyStatus(keyBits) {
  const parity = checkKeyParity(keyBits);
  const bad = parity.filter(byte => !byte.odd);
  const warnings = keyWarnings(keyBits);
  const lines = [];
  lines.push(bad.length === 0 ? `<p class="ok">Все байты имеют нечётную чётность.</p>` : `<p class="warning">Нарушена нечётная чётность в байтах: ${bad.map(byte => byte.index).join(", ")}.</p>`);
  warnings.forEach(warning => lines.push(`<p class="warning">${warning}</p>`));
  if (!warnings.length) lines.push(`<p class="hint">Явных учебных признаков слабого ключа не найдено.</p>`);
  $("keyStatus").innerHTML = lines.join("");
  $("parityGrid").innerHTML = parity.map(byte => `<div class="bit ${byte.odd ? "one" : ""}" title="${byte.ones} единиц">${byte.odd ? "odd" : "bad"}</div>`).join("");
}

function renderSubkeys() {
  $("subkeys").innerHTML = trace.subkeys.map(key => `
    <div class="subkey mono">
      <strong>K${String(key.round).padStart(2, "0")}</strong>
      <div>${bitsToHex(key.bits)}</div>
      <small>shift ${key.shift}</small>
    </div>
  `).join("");
}

function renderRound() {
  if (!trace) return;
  const index = Number($("roundRange").value) - 1;
  const round = trace.rounds[index];
  $("roundLabel").textContent = `Раунд ${round.round} (подключ K${round.keyRound})`;
  $("lIn").textContent = bitsToBinary(round.leftIn);
  $("rIn").textContent = bitsToBinary(round.rightIn);
  $("kRound").textContent = bitsToBinary(round.subkey);
  $("expanded").textContent = bitsToBinary(round.expanded);
  $("xored").textContent = bitsToBinary(round.xorWithKey);
  $("sboxBits").textContent = bitsToBinary(round.sboxOutput);
  $("pBits").textContent = bitsToBinary(round.pOutput);
  $("nextLR").textContent = `L=${bitsToHex(round.leftOut)}  R=${bitsToHex(round.rightOut)}`;
  renderRoundBits(round.rightIn, round.rightOut);
  renderSboxes(round.sboxActive);
}

function renderRoundBits(before, after) {
  $("roundBits").innerHTML = after.map((bit, index) => `
    <div class="bit ${bit ? "one" : ""} ${bit !== before[index] ? "changed" : ""}" title="позиция ${index + 1}: ${before[index]} → ${bit}">${bit}</div>
  `).join("");
}

function renderSboxes(active) {
  $("sboxes").innerHTML = DES_TABLES.SBOXES.map((box, index) => {
    const hit = active[index] || { row: -1, col: -1, value: "-" };
    const rows = box.map((row, r) => `
      <tr>
        <th>${r}</th>
        ${row.map((value, c) => `<td class="${r === hit.row && c === hit.col ? "active" : ""}">${value}</td>`).join("")}
      </tr>
    `).join("");
    return `
      <div class="trace-card">
        <h3>S${index + 1}: input ${hit.input || "------"} → ${hit.value}</h3>
        <table class="sbox-table mono">
          <thead><tr><th>r/c</th>${Array.from({ length: 16 }, (_, c) => `<th>${c}</th>`).join("")}</tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    `;
  }).join("");
}

function moveRound(delta) {
  const next = Math.min(16, Math.max(1, Number($("roundRange").value) + delta));
  $("roundRange").value = String(next);
  renderRound();
}

boot();
