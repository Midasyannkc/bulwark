// Builds Bulwark_Executive_Summary.pptx from out/report.json.
const fs = require("fs");
const path = require("path");
const pptxgen = require("pptxgenjs");
const SKILL = process.env.PPTX_SKILL_DIR;
const { applyTheme } = require(path.join(SKILL, "scripts", "apply_theme.js"));
const R = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "out", "report.json"), "utf8"));
const T = R.threat_model, I = R.incident_response, E = R.evidence, F = R.fhir;

const THEME = {
  name: "Bulwark", headFontFace: "Cambria", bodyFontFace: "Calibri",
  colors: { dk1: "16202E", lt1: "FFFFFF", dk2: "0F3B3A", lt2: "EEF5F4", accent1: "0F3B3A", accent2: "D9822B", accent3: "3B9C8E", accent4: "7F8CA3", accent5: "F0B561", accent6: "C24B3F", hlink: "0F3B3A", folHlink: "3B9C8E" },
};
const pres = new pptxgen();
pres.layout = "LAYOUT_16x9";
pres.title = "Bulwark Executive Summary";
pres.author = "Christian Kouadio Kouassi";
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
const C = pres.SchemeColor;

pres.defineSlideMaster({ title: "DARK", background: { color: C.text2 }, objects: [], slideNumber: { x: 9.2, y: 5.2, w: 0.5, h: 0.3, fontSize: 10, color: C.accent4 } });
pres.defineSlideMaster({
  title: "CONTENT", background: { color: C.background1 },
  objects: [{ placeholder: { options: { name: "title", type: "title", x: 0.6, y: 0.35, w: 8.8, h: 0.8, fontSize: 26, bold: true, color: C.text2, fontFace: "Cambria", margin: 0, valign: "top", align: "left" }, text: "" } }],
  slideNumber: { x: 9.2, y: 5.2, w: 0.5, h: 0.3, fontSize: 10, color: C.accent4 },
});
const card = (s, x, y, w, h, name, fill) => s.addShape(pres.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.08, fill: { color: fill || C.background2 }, line: { color: fill || C.background2, width: 0 }, objectName: name });
const txt = (s, t, o) => s.addText(t, { margin: 0, isTextBox: true, ...o });

// 1 Title
let s = pres.addSlide({ masterName: "DARK" });
txt(s, "Bulwark", { x: 0.7, y: 1.3, w: 8.6, h: 1.0, fontFace: "Cambria", fontSize: 54, bold: true, color: C.background1, objectName: "Title" });
txt(s, "Threat models, incident response, audit evidence and FHIR security for a virtual-care platform that holds PHI", { x: 0.7, y: 2.4, w: 8.2, h: 1.1, fontSize: 20, color: C.background2, objectName: "Subtitle" });
txt(s, "Python  |  FHIR  |  HIPAA  |  SOC 2  |  NIST 800-53  |  Christian Kouadio Kouassi", { x: 0.7, y: 4.55, w: 8.6, h: 0.4, fontSize: 14, color: C.accent5, objectName: "Byline" });
s.addNotes("Bulwark is a portfolio project built against a Senior Security Engineer posting at a virtual-care company. It fills the areas a cloud and IAM project does not cover.");

// 2 Headline numbers
s = pres.addSlide({ masterName: "CONTENT" });
s.addText("Every citation resolves, every fix was first a failing test", { placeholder: "title" });
const stats = [
  [`${T.citations_unverified}`, `unverified ATT&CK or NIST citations out of ${T.attack_techniques_cited.length + T.nist_controls_cited.length} used, checked against the real catalogs`],
  [`${I.strong_grade} vs ${I.weak_grade}`, "tabletop grade for a strong and a weak response to the same ransomware scenario"],
  [`${E.controls}`, `controls collected into a hashed evidence package; ${E.status.exception} exceptions found in the seeded snapshot`],
  [`${R.incidents}`, "defects found while building, each a failing test then a separate fix"],
];
stats.forEach(([big, label], i) => {
  const x = 0.6 + (i % 2) * 4.5, y = 1.4 + Math.floor(i / 2) * 1.75;
  card(s, x, y, 4.2, 1.5, `StatCard${i + 1}`);
  txt(s, big, { x: x + 0.25, y: y + 0.1, w: 3.7, h: 0.7, fontFace: "Cambria", fontSize: 36, bold: true, color: C.accent2, objectName: `StatValue${i + 1}` });
  txt(s, label, { x: x + 0.25, y: y + 0.82, w: 3.7, h: 0.62, fontSize: 13, color: C.text1, objectName: `StatLabel${i + 1}` });
});

// 3 Modules
s = pres.addSlide({ masterName: "CONTENT" });
s.addText("Four modules cover what a cloud-and-IAM project leaves open", { placeholder: "title" });
const steps = [["Threat modeling", "data-flow model to STRIDE threats"], ["Incident response", "runbooks, tabletop, breach clock"], ["Audit evidence", "SOC 2, HIPAA, HITRUST"], ["FHIR security", "validate, de-identify, test the API"], ["Integrations", "BAA, scopes, fields, webhooks"], ["Reference data", "NIST, ATT&CK, FHIR R4 (real)"]];
steps.forEach(([t, d], i) => {
  const col = i % 3, row = Math.floor(i / 3);
  const x = 0.6 + col * 3.0, y = 1.5 + row * 1.7;
  card(s, x, y, 2.7, 1.3, `Mod${i + 1}`, i === 5 ? C.accent5 : C.background2);
  s.addText([{ text: t, options: { bold: true, breakLine: true, fontSize: 16, color: C.text2 } }, { text: d, options: { fontSize: 12, color: C.text1 } }], { x: x + 0.1, y: y + 0.08, w: 2.5, h: 1.15, valign: "middle", align: "center", margin: 0, isTextBox: true, objectName: `ModText${i + 1}` });
});
txt(s, "Companion project Warden covers AWS IAM and Terraform, vulnerability prioritization, detection rules and the HIPAA safeguard map.", { x: 0.6, y: 4.75, w: 8.8, h: 0.4, fontSize: 12, color: C.accent4, objectName: "RuleNote" });

// 4 Threat model chart
s = pres.addSlide({ masterName: "CONTENT" });
s.addText("Threat model: a clean design, and what removing two controls does", { placeholder: "title" });
s.addChart(pres.charts.BAR, [{ name: "Threats", labels: ["As designed", "No TLS, no encryption at rest"], values: [T.threats, T.what_if_no_tls_no_encryption_threats] }],
  { x: 0.6, y: 1.3, w: 5.4, h: 3.8, barDir: "col", chartColors: ["0F3B3A"], showLegend: false, showValue: true, dataLabelPosition: "outEnd", dataLabelFontFace: "+mn-lt", dataLabelFontSize: 14,
    catAxisLabelFontFace: "+mn-lt", catAxisLabelFontSize: 12, valAxisHidden: true, valAxisMinVal: 0, valGridLine: { style: "none" }, catGridLine: { style: "none" }, objectName: "ThreatChart" });
card(s, 6.3, 1.4, 3.2, 3.6, "ThreatCard");
s.addText([
  { text: `${T.elements} elements, ${T.flows} flows`, options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: "Threats are mapped to real ATT&CK techniques and NIST controls. Mutation tests remove TLS from every flow and encryption from every store and require a finding each time.", options: { breakLine: true } },
  { text: "A typo that hid a flow", options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: "A lowercase data class once removed a PHI flow from every rule. The model is validated first now.", options: {} },
], { x: 6.45, y: 1.55, w: 2.9, h: 3.4, fontSize: 11.5, color: C.text1, paraSpaceAfter: 6, valign: "top", margin: 0, isTextBox: true, objectName: "ThreatNotes" });

// 5 IR
s = pres.addSlide({ masterName: "CONTENT" });
s.addText("Incident response: the scoring tells a strong team from a weak one", { placeholder: "title" });
s.addChart(pres.charts.BAR, [{ name: "Grade", labels: ["Strong play", "Weak play"], values: [I.strong_grade, I.weak_grade] }],
  { x: 0.6, y: 1.3, w: 5.0, h: 3.8, barDir: "col", chartColors: ["3B9C8E", "C24B3F"], showLegend: false, showValue: true, dataLabelPosition: "outEnd", dataLabelFontFace: "+mn-lt", dataLabelFontSize: 14,
    catAxisLabelFontFace: "+mn-lt", catAxisLabelFontSize: 12, valAxisHidden: true, valAxisMinVal: 0, valAxisMaxVal: 115, valGridLine: { style: "none" }, catGridLine: { style: "none" }, objectName: "IrChart" });
card(s, 5.9, 1.4, 3.6, 3.6, "IrCard");
s.addText([
  { text: `${I.runbooks} runbooks, ${I.lint_findings} lint findings`, options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: "Storage exposure, account compromise and ransomware, each across seven phases with owners and evidence.", options: { breakLine: true } },
  { text: "The weak play", options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: "Wiped hosts before preserving evidence, waited for forensics to start the breach clock, and paid on its own authority. The simulator found a gap in my own runbook too: no explicit evidence-preservation step.", options: {} },
], { x: 6.05, y: 1.55, w: 3.3, h: 3.4, fontSize: 11.5, color: C.text1, paraSpaceAfter: 6, valign: "top", margin: 0, isTextBox: true, objectName: "IrNotes" });
s.addNotes("Breach notification deadlines are computed from the discovery date as an engineering aid. Counsel decides.");

// 6 Evidence
s = pres.addSlide({ masterName: "CONTENT" });
s.addText("Audit evidence: findings an auditor would find first", { placeholder: "title" });
const stKeys = Object.keys(E.status);
s.addChart(pres.charts.BAR, [{ name: "Controls", labels: stKeys.map((k) => k[0].toUpperCase() + k.slice(1)), values: stKeys.map((k) => E.status[k]) }],
  { x: 0.6, y: 1.3, w: 4.8, h: 3.8, barDir: "col", chartColors: ["0F3B3A"], showLegend: false, showValue: true, dataLabelPosition: "outEnd", dataLabelFontFace: "+mn-lt", dataLabelFontSize: 14,
    catAxisLabelFontFace: "+mn-lt", catAxisLabelFontSize: 12, valAxisHidden: true, valAxisMinVal: 0, valGridLine: { style: "none" }, catGridLine: { style: "none" }, objectName: "EvidenceChart" });
card(s, 5.7, 1.4, 3.8, 3.6, "EvidenceCard");
s.addText([
  { text: "Hashed, mapped, expiring", options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: `${E.controls} controls map to SOC 2, HIPAA and HITRUST categories. Each artifact carries a SHA-256, and stale evidence is flagged by control frequency.`, options: { breakLine: true } },
  { text: "Honest coverage", options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: `${E.baseline_coverage.covered} of ${E.baseline_coverage.baseline_base_controls} base controls in the real NIST Moderate baseline (${E.baseline_coverage.percent} percent). An empty population is untestable, never a pass.`, options: {} },
], { x: 5.85, y: 1.55, w: 3.5, h: 3.4, fontSize: 11.5, color: C.text1, paraSpaceAfter: 6, valign: "top", margin: 0, isTextBox: true, objectName: "EvidenceNotes" });

// 7 FHIR
s = pres.addSlide({ masterName: "CONTENT" });
s.addText("FHIR security: probes against the in-process API", { placeholder: "title" });
const hdr = (t) => ({ text: t, options: { bold: true, color: C.background1, fill: { color: C.text2 } } });
const rows = [[hdr("Probe"), hdr("Result")]];
Object.entries(F.api_probe_status).forEach(([k, v]) => rows.push([{ text: k }, { text: String(v), options: { bold: true, color: v === 200 ? "2E7D5B" : "C24B3F" } }]));
s.addTable(rows, { x: 0.6, y: 1.35, w: 5.6, colW: [4.4, 1.2], fontSize: 12, fontFace: "Calibri", color: "16202E", border: { type: "solid", color: "D5DEDD", pt: 0.75 }, rowH: 0.45, valign: "middle", objectName: "ProbeTable" });
card(s, 6.5, 1.4, 3.0, 3.6, "FhirCard");
s.addText([
  { text: "Real spec, real checks", options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: `Resources validate against ${F.r4_resources_loaded} real R4 definitions. De-identification leaves ${F.deid_leaks} identifiers; PHI in audit log: ${F.phi_in_audit_log ? "yes" : "no"}.`, options: { breakLine: true } },
  { text: "Partners", options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: `Findings: lab vendor ${F.partners["lab-vendor"]}, EHR partner ${F.partners["ehr-partner"]}, marketing vendor ${F.partners["marketing-analytics"]} (no BAA).`, options: {} },
], { x: 6.65, y: 1.55, w: 2.7, h: 3.4, fontSize: 11.5, color: C.text1, paraSpaceAfter: 6, valign: "top", margin: 0, isTextBox: true, objectName: "FhirNotes" });
s.addNotes("The API returns 404 rather than 403 for another patient's record so that existence is not revealed.");

// 8 Incidents
s = pres.addSlide({ masterName: "CONTENT" });
s.addText("Ten defects, each reproduced then fixed", { placeholder: "title" });
const groups = [
  ["Seeded in the API (4)", "Cross-patient reads (BOLA)\nRead-only token could write\nBulk export with no login\nPHI in audit log and errors"],
  ["Found in de-identification (2)", "Names in free text survived\nTimestamps kept the full date"],
  ["Found in the validator (1)", "valueBanana passed as a choice type"],
  ["Found in my own tooling (3)", "Data class typo hid a PHI flow\nRunbook without preservation step\nEmpty population reported pass"],
];
groups.forEach(([t, body], i) => {
  const x = 0.6 + (i % 2) * 4.5, y = 1.25 + Math.floor(i / 2) * 1.9;
  card(s, x, y, 4.3, 1.75, `Group${i + 1}`);
  txt(s, t, { x: x + 0.2, y: y + 0.1, w: 3.9, h: 0.35, fontFace: "Cambria", fontSize: 15, bold: true, color: C.accent2, objectName: `GroupTitle${i + 1}` });
  s.addText(body.split("\n").map((l, j, arr) => ({ text: l, options: { breakLine: j < arr.length - 1 } })), { x: x + 0.2, y: y + 0.48, w: 3.95, h: 1.2, fontSize: 11.5, color: C.text1, valign: "top", margin: 0, isTextBox: true, objectName: `GroupBody${i + 1}` });
});
txt(s, "A script re-runs every reproduce and fix commit in a clean checkout to prove it.", { x: 0.6, y: 5.17, w: 8.2, h: 0.25, fontSize: 10, color: C.accent4, objectName: "IncNote" });

// 9 Limits
s = pres.addSlide({ masterName: "DARK" });
txt(s, "What this shows, and what it does not", { x: 0.7, y: 0.5, w: 8.6, h: 0.8, fontFace: "Cambria", fontSize: 32, bold: true, color: C.background1, objectName: "ClosingTitle" });
s.addText([
  { text: "Shows", options: { bold: true, color: C.accent5, breakLine: true, fontSize: 18 } },
  { text: "Threat modeling that cites real catalogs", options: { bullet: true, breakLine: true } },
  { text: "Runbooks, a tabletop and a breach clock", options: { bullet: true, breakLine: true } },
  { text: "Evidence an auditor can verify", options: { bullet: true } },
], { x: 0.7, y: 1.5, w: 4.2, h: 2.7, fontSize: 15, color: C.background1, paraSpaceAfter: 8, valign: "top", margin: 0, isTextBox: true, objectName: "ShowsText" });
s.addText([
  { text: "Does not show", options: { bold: true, color: C.accent5, breakLine: true, fontSize: 18 } },
  { text: "Five years of healthcare security work or a certification", options: { bullet: true, breakLine: true } },
  { text: "A live AWS account, SIEM or EHR", options: { bullet: true, breakLine: true } },
  { text: "A real team under incident pressure", options: { bullet: true } },
], { x: 5.2, y: 1.5, w: 4.2, h: 2.7, fontSize: 15, color: C.background1, paraSpaceAfter: 8, valign: "top", margin: 0, isTextBox: true, objectName: "NotShownText" });
txt(s, "87 tests  |  10 incidents  |  sole-author git history  |  nothing pushed", { x: 0.7, y: 4.55, w: 8.6, h: 0.4, fontSize: 14, color: C.accent3, objectName: "Footer" });

(async () => {
  const out = path.join(__dirname, "..", "Bulwark_Executive_Summary.pptx");
  await pres.writeFile({ fileName: out });
  await applyTheme(out, THEME);
  console.log("wrote", out);
})();
