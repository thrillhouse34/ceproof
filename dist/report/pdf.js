"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NO_BROWSER_MESSAGE = void 0;
exports.findChromeExecutable = findChromeExecutable;
exports.buildFooterTemplate = buildFooterTemplate;
exports.renderAnnexPdf = renderAnnexPdf;
const fs = __importStar(require("fs"));
const puppeteer_core_1 = __importDefault(require("puppeteer-core"));
const branding_1 = require("../branding");
// ─────────────────────────────────────────────────────────────────────────────
// ceproof PDF renderer (Milestone 2) — prints the Annex VII technical
// documentation pack / Annex V Declaration of Conformity draft HTML
// (`renderAnnexHtml`, html.ts) to PDF.
//
// The REAL renderer. It drives an ALREADY-INSTALLED Chrome / Chromium / Edge
// via `puppeteer-core`. We use `puppeteer-core` — never plain `puppeteer` —
// specifically because it does NOT download a bundled Chromium on install.
// The user's own browser is located by `findChromeExecutable` and passed via
// `executablePath`; if none is found we throw a clear, honest error telling
// the user to use a non-PDF format instead.
//
// PER-PAGE FOOTER — the load-bearing distinction (do NOT "simplify" this):
// The provenance footer with a real per-page page number is produced HERE,
// via Puppeteer's `page.pdf({ displayHeaderFooter: true, footerTemplate })`.
// That is a genuinely different, actually-working mechanism from CSS `@page`
// margin boxes, which Chrome's print engine does NOT support for arbitrary
// injected text/counters. `footerTemplate` is an HTML string in which
// Puppeteer substitutes the live page number into
// `<span class="pageNumber"></span>`. This is the ONLY place the exact
// footer text ("ceproof <tool> · CRA data <data> · <timestamp> · page N")
// can be implemented literally and correctly. The standalone HTML file
// (html.ts) therefore carries only a STATIC provenance footer — true
// cross-browser per-page numbering is impossible in portable print CSS, so
// nobody should later try to "fix" the HTML print CSS to add it.
// ─────────────────────────────────────────────────────────────────────────────
// Standard install locations to probe, per OS. First existing file wins. The
// list is platform-gated (see `findChromeExecutable`) so we never do pointless
// `fs.existsSync` calls for paths that cannot exist on the current OS.
const MACOS_PATHS = [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
];
const LINUX_PATHS = [
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/microsoft-edge',
    '/usr/bin/microsoft-edge-stable',
    '/snap/bin/chromium',
];
const WINDOWS_PATHS = [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
];
/**
 * Locate an installed Chrome / Chromium / Edge executable at a standard OS
 * location, or `undefined` if none is present. Only the current platform's
 * candidate list is probed.
 */
function findChromeExecutable() {
    let candidates;
    switch (process.platform) {
        case 'darwin':
            candidates = MACOS_PATHS;
            break;
        case 'win32':
            candidates = WINDOWS_PATHS;
            break;
        default:
            // Linux and every other Unix-like platform use the Linux locations.
            candidates = LINUX_PATHS;
            break;
    }
    for (const candidate of candidates) {
        if (fs.existsSync(candidate))
            return candidate;
    }
    return undefined;
}
/**
 * The exact, honest message surfaced when no browser is installed. Thrown as
 * an `Error` (caught by the `report` command's render-loop try/catch, which
 * turns any thrown error into an exit-2 tool error per the M2 brief's
 * addendum D). Names both non-PDF format flags so the message is actionable
 * regardless of which pack the user was trying to render — `report --format
 * annex7-pdf` falls back to `annex7`, `doc-pdf` falls back to `doc`.
 */
exports.NO_BROWSER_MESSAGE = 'No installed Chrome, Chromium, or Edge browser was found at any standard location. ' +
    'PDF generation requires one of these to be installed. ' +
    'Use the non-PDF format instead (--format annex7 or --format doc) — no dependencies required.';
/**
 * Escape a value for safe interpolation into the footer HTML template. The
 * provenance fields (tool version, data version, ISO timestamp, release
 * label) never contain HTML-special characters in practice, but escaping
 * keeps the template robust if that ever changes and avoids any chance of
 * the injected text breaking the footer markup.
 */
function escapeHtml(s) {
    return s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
/**
 * Build the per-page footer template: the literal required provenance text
 * with a live page number injected into `<span class="pageNumber"></span>`
 * (Puppeteer substitutes the real per-page value into that span at print
 * time).
 *
 * Exported so it can be unit-tested directly. That matters because the
 * rendered PDF's text is NOT greppable: Chrome subsets its fonts and encodes
 * text as glyph indices inside Flate-compressed content streams, so the
 * footer string cannot be recovered from the output bytes without a full
 * PDF-parsing library (deliberately not added for this). Testing the
 * template we hand to Puppeteer, plus asserting the PDF really is a valid
 * multi-page document, is the sound split: the exact wording is ours to get
 * right and is tested here, while substituting `pageNumber` is Puppeteer's
 * documented contract.
 *
 * A wrapping div with an explicit font-size is REQUIRED — Puppeteer's
 * default header/footer font-size is effectively 0, so an unstyled template
 * renders invisibly.
 */
function buildFooterTemplate(provenance) {
    return (`<div style="width:100%;font-size:8px;color:#5b6472;` +
        `font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;` +
        `padding:0 14mm;text-align:center;">` +
        `${escapeHtml(branding_1.PRODUCT_NAME)} ${escapeHtml(provenance.toolVersion)} &middot; ` +
        `CRA data ${escapeHtml(provenance.dataVersion)} &middot; ` +
        `${escapeHtml(provenance.scanTimestamp)} &middot; ` +
        `page <span class="pageNumber"></span>` +
        `</div>`);
}
/**
 * Render the already-produced HTML document to a PDF Buffer.
 *
 * Signature decision — takes BOTH the rendered `html` string AND `content`:
 *   - `html` is what Puppeteer actually prints. Puppeteer prints HTML, not
 *     `AnnexPackContent`, so the renderer must receive the HTML `html.ts`'s
 *     `renderAnnexHtml` produced (the call site composes
 *     `renderAnnexPdf(renderAnnexHtml(content), content)`).
 *   - `content` is needed ONLY for `content.provenance` (the footer's tool
 *     version / data version / timestamp). Re-deriving these from the HTML
 *     string would be brittle string-scraping; passing the structured data
 *     is clean and keeps this function from having to know anything about
 *     the HTML's shape.
 * Taking both (rather than taking `AnnexPackContent` and calling
 * `renderAnnexHtml` internally) keeps `renderAnnexPdf` a focused "print this
 * HTML" function with no dependency on the HTML renderer, and avoids
 * rendering the HTML twice.
 *
 * Throws `Error(NO_BROWSER_MESSAGE)` if no browser is installed.
 */
async function renderAnnexPdf(html, content) {
    const executablePath = findChromeExecutable();
    if (!executablePath) {
        throw new Error(exports.NO_BROWSER_MESSAGE);
    }
    const footerTemplate = buildFooterTemplate(content.provenance);
    // An empty (but non-empty-string) header suppresses Chrome's built-in
    // default header (date + document title) that would otherwise appear
    // whenever displayHeaderFooter is true and no headerTemplate is supplied.
    const headerTemplate = '<div></div>';
    const browser = await puppeteer_core_1.default.launch({ executablePath, headless: true });
    try {
        const page = await browser.newPage();
        // WAIT CONDITION — deviates from `networkidle0` for a real API reason,
        // not a shortcut: puppeteer-core v25's `setContent` type EXPLICITLY
        // excludes the networkidle values
        // (`Exclude<PuppeteerLifeCycleEvent, 'networkidle0' | 'networkidle2'>`,
        // see SetContentWaitForOptions in its types.d.ts) — upstream removed them
        // from setContent because network-idle semantics are meaningless for
        // content set directly rather than navigated to. `'load'` is the
        // accepted value and the correct one here: it waits for the document and
        // all its resources, which for this fully self-contained, zero-external-
        // request document resolves immediately while still being the strongest
        // guarantee the API offers.
        await page.setContent(html, { waitUntil: 'load' });
        const pdf = await page.pdf({
            format: 'A4',
            printBackground: true,
            displayHeaderFooter: true,
            headerTemplate,
            footerTemplate,
            // Bottom margin is the largest to leave room for the footer band; the
            // rest match the HTML's own ~16mm print margins.
            margin: { top: '16mm', bottom: '20mm', left: '14mm', right: '14mm' },
        });
        // page.pdf() returns a Uint8Array in puppeteer-core v25; the CLI writes a
        // Buffer, so normalize here.
        return Buffer.from(pdf);
    }
    finally {
        // Always close the browser, even if setContent/pdf threw.
        await browser.close();
    }
}
//# sourceMappingURL=pdf.js.map