// Remonce local signer UI.
//
// Every value shown comes from this signer's config (/api/commands), from a
// token the user pasted, from a signing result, or from the agent's stream.
// Values decoded client-side from a bundle are what the bundle *claims*; the
// agent is the one that verifies them.
//
// Signing never happens in the page: /api/sign/begin parks the action on the
// server and returns an identity-provider URL. The user re-authenticates, the
// server signs with a one-time key, and the browser comes back with
// ?sign_result=<id>, read once from /api/sign/result/<id>.

'use strict';

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);

// h('div', {class: 'x', onclick: fn}, child, 'text', [more]) — text is always
// inserted as text nodes, never parsed as HTML.
function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
        if (v === null || v === undefined || v === false) continue;
        if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
        else if (k === 'class') el.className = v;
        else if (k === 'value') el.value = v;
        else if (v === true) el.setAttribute(k, '');
        else el.setAttribute(k, v);
    }
    append(el, children);
    return el;
}

function append(el, children) {
    for (const c of children.flat()) {
        if (c === null || c === undefined || c === false) continue;
        el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
}

function clear(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
    return el;
}

const ICONS = {
    sign: 'M2 11.5V14h2.5L12 6.5 9.5 4 2 11.5zM9.5 4l1.8-1.8a1 1 0 0 1 1.4 0l1.1 1.1a1 1 0 0 1 0 1.4L12 6.5',
    fingerprint: 'M4 9c0-2.2 1.8-4 4-4s4 1.8 4 4v2M6 10v2M8 7v5M10 10v2M4 6c1-1.5 2.5-2.5 4-2.5s3 1 4 2.5',
    clock: 'M8 2a6 6 0 1 0 0 12A6 6 0 0 0 8 2zM8 5v3l2 1.5',
    target: 'M8 2.5a5.5 5.5 0 1 0 0 11 5.5 5.5 0 0 0 0-11zM8 6a2 2 0 1 0 0 4 2 2 0 0 0 0-4zM8 1v2M8 13v2M1 8h2M13 8h2',
    params: 'M3 4h10M3 8h6M3 12h8',
    search: 'M7 2.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9zM13 13l-2.7-2.7',
    close: 'M3.5 3.5 12.5 12.5M12.5 3.5l-9 9',
    copy: 'M6.5 5h5A1.5 1.5 0 0 1 13 6.5v5a1.5 1.5 0 0 1-1.5 1.5h-5A1.5 1.5 0 0 1 5 11.5v-5A1.5 1.5 0 0 1 6.5 5zM3 10V4a1 1 0 0 1 1-1h6',
    download: 'M8 2v8m0 0L5 7m3 3 3-3M3 12.5h10',
    play: 'M4 2.5v11l9-5.5-9-5.5z',
    terminal: 'M3 3h10a1.5 1.5 0 0 1 1.5 1.5v7A1.5 1.5 0 0 1 13 13H3a1.5 1.5 0 0 1-1.5-1.5v-7A1.5 1.5 0 0 1 3 3zM4 6.5 6 8 4 9.5M8 10h3',
    info: 'M8 2a6 6 0 1 0 0 12A6 6 0 0 0 8 2zM8 7v4M8 5h.01',
    warn: 'M8 2 1.5 13.5h13L8 2zM8 6.5v3.5M8 11.8h.01',
    check: 'm3 8 3.5 3.5L13 5',
    file: 'M9 2H4a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V6L9 2zM9 2v4h4',
    plus: 'M8 3v10M3 8h10',
    revoke: 'M8 2a6 6 0 1 0 0 12A6 6 0 0 0 8 2zM3.8 3.8l8.4 8.4',
    refresh: 'M13 3v3.5H9.5M3 13V9.5h3.5M12.5 6.5A5 5 0 0 0 3.8 5M3.5 9.5A5 5 0 0 0 12.2 11',
    down: 'M4 6l4 4 4-4',
};

function icon(name) {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('class', 'icon');
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('fill', name === 'play' ? 'currentColor' : 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.4');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    const path = document.createElementNS(ns, 'path');
    path.setAttribute('d', ICONS[name]);
    svg.append(path);
    return svg;
}

let toastTimer = null;
function toast(message, isError) {
    document.querySelectorAll('.toast').forEach(t => t.remove());
    const t = h('div', { class: 'toast' + (isError ? ' error' : ''), role: 'status' }, message);
    document.body.append(t);
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.remove(), isError ? 7000 : 2600);
}

function notice(kind, ...content) {
    const name = { ok: 'check', warn: 'warn', error: 'warn' }[kind] || 'info';
    return h('div', { class: 'notice ' + (kind || '') }, icon(name), h('div', {}, ...content));
}

async function copyText(text, label) {
    try {
        await navigator.clipboard.writeText(text);
        toast(label || 'Copied');
    } catch (_) {
        toast('Copy failed — your browser blocked clipboard access', true);
    }
}

// Handoff files: remonce-<command>-<id prefix>.<kind>.json, where kind is
// request (unsigned), approval (signed) or cosigned (ready to run). The
// content is the same JSON the CLI reads (`remonce cosign --bundle FILE`).
function tokenFileName(obj) {
    const t = classifyToken(obj);
    const command = t.kind === 'draft' ? t.command : t.bundle.approver.command;
    const name = String(command.command || 'command').replace(/[^A-Za-z0-9._-]+/g, '_');
    const id = String(command.id || '').replace(/[^A-Za-z0-9]/g, '').slice(0, 8);
    const kind = t.kind === 'draft' ? 'request' : (t.bundle.operator ? 'cosigned' : 'approval');
    return `remonce-${name}${id ? '-' + id : ''}.${kind}.json`;
}

function saveTokenFile(obj) {
    const filename = tokenFileName(obj);
    downloadJson(filename, obj);
    toast('Saved ' + filename);
}

function downloadJson(filename, obj) {
    const url = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' }));
    const a = h('a', { href: url, download: filename });
    document.body.append(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

function fmtDuration(secs) {
    if (!secs && secs !== 0) return '';
    const units = [['d', 86400], ['h', 3600], ['m', 60], ['s', 1]];
    const parts = [];
    let left = secs;
    for (const [u, n] of units) {
        if (left >= n) {
            parts.push(Math.floor(left / n) + u);
            left %= n;
        }
        if (parts.length === 2) break;
    }
    return parts.join(' ') || '0s';
}

function fmtTime(value) {
    const d = value instanceof Date ? value : new Date(value);
    if (isNaN(d)) return String(value);
    return d.toLocaleString(undefined, {
        year: 'numeric', month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
}

function glyph(name) {
    const words = String(name).split(/[^A-Za-z0-9]+/).filter(Boolean);
    if (words.length >= 2) return (words[0][0] + words[1][0]).toLowerCase();
    return String(name).slice(0, 2).toLowerCase();
}

// Windows verbatim paths (\\?\C:\...) are exact but noisy; show them plainly.
function displayPath(p) {
    return String(p).replace(/^\\\\\?\\/, '');
}

function fmtPredicate(p) {
    const v = typeof p.value === 'string' ? p.value : JSON.stringify(p.value);
    return `${p.claim} ${p.op === 'contains' ? 'contains' : '='} ${v}`;
}

// ---------------------------------------------------------------------------
// Tokens: base64(JSON) or raw JSON; drafts and signed bundles
// ---------------------------------------------------------------------------

function encodeToken(obj) {
    const bytes = new TextEncoder().encode(JSON.stringify(obj));
    let bin = '';
    bytes.forEach(b => { bin += String.fromCharCode(b); });
    return btoa(bin);
}

function decodeToken(raw) {
    const text = raw.trim();
    if (!text) throw new Error('Nothing to read — paste a token first');
    if (text.startsWith('{')) return JSON.parse(text);
    let bin;
    try {
        bin = atob(text.replace(/\s+/g, ''));
    } catch (_) {
        throw new Error('Not JSON or base64');
    }
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, c => c.charCodeAt(0))));
}

// { kind: 'draft', command, operator_requires } | { kind: 'bundle', bundle }
function classifyToken(obj) {
    if (obj && obj.approver && obj.approver.signature) {
        return { kind: 'bundle', bundle: { approver: obj.approver, operator: obj.operator || null } };
    }
    if (obj && obj.signature && obj.command) {
        return { kind: 'bundle', bundle: { approver: obj, operator: null } };
    }
    if (obj && obj.command && typeof obj.command === 'object') {
        return { kind: 'draft', command: obj.command, operator_requires: obj.operator_requires || null };
    }
    if (obj && typeof obj.command === 'string') {
        return { kind: 'draft', command: obj, operator_requires: null };
    }
    throw new Error('Not a Remonce request or approval');
}

function jwtClaims(jwt) {
    try {
        const part = jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
        const bin = atob(part + '='.repeat((4 - part.length % 4) % 4));
        return JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, c => c.charCodeAt(0))));
    } catch (_) {
        return null;
    }
}

function claimName(claims) {
    return claims ? (claims.username || claims.sub || 'unknown') : 'unknown';
}

function sortKeys(v) {
    if (Array.isArray(v)) return v.map(sortKeys);
    if (v && typeof v === 'object') {
        const out = {};
        Object.keys(v).sort().forEach(k => { out[k] = sortKeys(v[k]); });
        return out;
    }
    return v;
}

// The payload an approver signs: {command, operator_requires} with sorted
// keys (sent compact; shown indented).
function signedPayloadText(command, operatorRequires) {
    return JSON.stringify(sortKeys({ command, operator_requires: operatorRequires }), null, 2);
}

// ---------------------------------------------------------------------------
// Agent selection and API calls
// ---------------------------------------------------------------------------

const AGENT_KEY = 'remonce.agentUrl';

function agentUrl() {
    const input = $('agent-url');
    return input ? input.value.trim() : '';
}

function initAgentField() {
    const input = $('agent-url');
    if (!input) return;
    let stored = null;
    try { stored = localStorage.getItem(AGENT_KEY); } catch (_) { /* storage blocked */ }
    input.value = stored || document.body.dataset.agentUrl || '';
    input.addEventListener('change', () => {
        try { localStorage.setItem(AGENT_KEY, input.value.trim()); } catch (_) { /* ignore */ }
    });
}

async function errorText(res) {
    const text = await res.text();
    try {
        const data = JSON.parse(text);
        if (data && data.error) return data.error;
    } catch (_) { /* plain text */ }
    return text.replace(/^Error:\s*/, '') || `HTTP ${res.status}`;
}

async function api(path, options) {
    const res = await fetch(path, options);
    if (res.status === 401 && !path.startsWith('/api/agent/')) {
        window.location.assign('/auth/login');
        throw new Error('Session expired — logging in again');
    }
    if (!res.ok) throw new Error(await errorText(res));
    return res.json();
}

function postJson(path, body) {
    return api(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
}

let commandsCache = null;
async function loadCommands() {
    if (!commandsCache) commandsCache = await api('/api/commands');
    return commandsCache;
}

async function commandInfo(name) {
    try {
        return (await loadCommands()).find(c => c.name === name) || null;
    } catch (_) {
        return null;
    }
}

// Park a signing action and go re-authenticate. Only returns on failure.
async function beginSigning(action) {
    const { authorize_url } = await postJson('/api/sign/begin', action);
    window.location.assign(authorize_url);
}

async function executeBundle(bundle) {
    const res = await postJson('/api/agent/execute', { agent_url: agentUrl(), bundle });
    const params = new URLSearchParams({ id: res.message });
    if (agentUrl()) params.set('agent_url', agentUrl());
    window.location.assign('/ui/monitor?' + params.toString());
}

// Read the one-time signing result named in ?sign_result, stripping it from
// the URL. Returns null when there is none.
async function takeSignResult() {
    const params = new URLSearchParams(window.location.search);
    const id = params.get('sign_result');
    if (!id) return null;
    params.delete('sign_result');
    const rest = params.toString();
    history.replaceState(null, '', window.location.pathname + (rest ? '?' + rest : ''));
    try {
        return await api('/api/sign/result/' + encodeURIComponent(id));
    } catch (e) {
        return { outcome: 'error', message: 'Could not load the signing result: ' + e.message };
    }
}

// Load a token into `textarea` from a file (button or drag-and-drop onto
// `dropZone`) or from a paste anywhere on the page, then call `onLoad`.
// Files are read locally; nothing is uploaded.
const MAX_TOKEN_FILE = 1024 * 1024;
function acceptTokens(textarea, fileButton, fileInput, dropZone, onLoad) {
    const load = (text) => {
        textarea.value = text.trim();
        onLoad();
    };
    const readFile = async (file) => {
        if (!file) return;
        if (file.size > MAX_TOKEN_FILE) {
            toast(`${file.name} is too large to be a Remonce file`, true);
            return;
        }
        load(await file.text());
    };

    // Pasting straight into the box reviews it too.
    textarea.addEventListener('paste', () => setTimeout(onLoad));
    fileButton.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => {
        readFile(fileInput.files[0]);
        fileInput.value = '';
    });

    let depth = 0;
    const hasFiles = (e) => [...(e.dataTransfer?.types || [])].includes('Files');
    dropZone.addEventListener('dragenter', (e) => {
        if (!hasFiles(e)) return;
        e.preventDefault();
        depth++;
        dropZone.classList.add('dragover');
    });
    dropZone.addEventListener('dragover', (e) => { if (hasFiles(e)) e.preventDefault(); });
    dropZone.addEventListener('dragleave', () => {
        if (--depth <= 0) { depth = 0; dropZone.classList.remove('dragover'); }
    });
    dropZone.addEventListener('drop', (e) => {
        if (!hasFiles(e)) return;
        e.preventDefault();
        depth = 0;
        dropZone.classList.remove('dragover');
        readFile(e.dataTransfer.files[0]);
    });
    // A file dropped outside the zone must not navigate the page away.
    window.addEventListener('dragover', (e) => { if (hasFiles(e)) e.preventDefault(); });
    window.addEventListener('drop', (e) => { if (hasFiles(e)) e.preventDefault(); });

    document.addEventListener('paste', (e) => {
        const t = e.target;
        if (t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement || t?.isContentEditable) return;
        const text = e.clipboardData?.getData('text');
        if (text && text.trim()) {
            e.preventDefault();
            load(text);
        }
    });
}

// Pass a bundle to another page without putting it in the URL.
const HANDOFF_KEY = 'remonce.handoff';
function handOff(page, bundle) {
    try { sessionStorage.setItem(HANDOFF_KEY, encodeToken(bundle)); } catch (_) { /* ignore */ }
    window.location.assign(page);
}
function takeHandOff() {
    try {
        const v = sessionStorage.getItem(HANDOFF_KEY);
        sessionStorage.removeItem(HANDOFF_KEY);
        return v;
    } catch (_) {
        return null;
    }
}

// ---------------------------------------------------------------------------
// Shared rendering: what a request / approval says
// ---------------------------------------------------------------------------

function modeText(req) {
    if (!req) return 'Self-execute only — the approver runs it; it cannot be co-signed';
    if (!req.any_of || req.any_of.length === 0) return 'Delegated — any operator may co-sign and run it (policy still applies)';
    return 'Delegated — the operator must match one of: ' + req.any_of.map(fmtPredicate).join(' · ');
}

function factRows(rows) {
    const dl = h('dl', { class: 'facts' });
    rows.filter(Boolean).forEach(([k, v, mono]) => {
        dl.append(h('dt', {}, k));
        const dd = h('dd', { class: mono ? 'mono' : '' });
        if (v === null || v === undefined || v === '') dd.append(h('span', { class: 'none' }, 'none'));
        else append(dd, [v]);
        dl.append(dd);
    });
    return dl;
}

function commandFacts(command, operatorRequires) {
    const params = command.params && Object.keys(command.params).length
        ? Object.entries(command.params).map(([k, v]) => `${k}=${v}`).join('  ')
        : null;
    const targets = Array.isArray(command.target_machines) && command.target_machines.length
        ? command.target_machines.join(', ')
        : null;
    return [
        ['Command', command.command, true],
        ['Execution ID', command.id, true],
        ['Target machines', targets, true],
        ['Parameters', params, true],
        command.not_before ? ['Not before', fmtTime(command.not_before)] : null,
        command.not_after ? ['Not after', fmtTime(command.not_after)] : null,
        ['Who runs it', modeText(operatorRequires)],
    ];
}

function bundleSignerRows(bundle) {
    const a = jwtClaims(bundle.approver.id_token);
    const rows = [
        ['Approved by', claimName(a) + (a && a.groups ? '  ·  groups: ' + a.groups.join(', ') : '')],
        a && a.iat ? ['Approver logged in', fmtTime(a.iat * 1000)] : null,
    ];
    if (bundle.operator) {
        const o = jwtClaims(bundle.operator.id_token);
        rows.push(['Co-signed by', claimName(o)]);
        if (o && o.iat) rows.push(['Operator logged in', fmtTime(o.iat * 1000)]);
    }
    return rows;
}

function panelTitle(name, description) {
    return h('div', { class: 'panel-title' },
        h('div', { class: 'cmd-glyph' }, glyph(name)),
        h('div', { class: 'text' },
            h('div', { class: 'n' }, name),
            description ? h('div', { class: 'd' }, description) : null));
}

// Problems an agent will certainly reject, found without contacting it.
async function requestProblems(command) {
    const problems = [];
    if (!Array.isArray(command.target_machines) || command.target_machines.length === 0) {
        problems.push('No target machines. Agents refuse approvals without target_machines.');
    }
    const info = await commandInfo(command.command);
    if (!info) {
        problems.push(`This signer's configuration doesn't list '${command.command}'. ` +
            'Agents only run commands they are configured with.');
    }
    return { problems, info };
}

// ---------------------------------------------------------------------------
// Signed result (review page) and the sealed signet
// ---------------------------------------------------------------------------

function sealedSignet() {
    const ns = 'http://www.w3.org/2000/svg';
    const mk = (tag, attrs) => {
        const el = document.createElementNS(ns, tag);
        Object.entries(attrs).forEach(([k, v]) => el.setAttribute(k, v));
        return el;
    };
    const svg = mk('svg', { viewBox: '0 0 100 100', 'aria-hidden': 'true' });
    const defs = mk('defs', {});
    const dough = mk('radialGradient', { id: 'doughG', cx: '45%', cy: '38%', r: '60%' });
    [['0%', 'oklch(0.96 0.1 85)'], ['70%', 'oklch(0.82 0.14 70)'], ['100%', 'oklch(0.58 0.12 55)']]
        .forEach(([o, c]) => dough.append(mk('stop', { offset: o, 'stop-color': c })));
    const core = mk('radialGradient', { id: 'coreG', cx: '35%', cy: '30%' });
    [['0%', 'oklch(0.98 0.1 150)'], ['100%', 'oklch(0.78 0.18 150)']]
        .forEach(([o, c]) => core.append(mk('stop', { offset: o, 'stop-color': c })));
    defs.append(dough, core);
    svg.append(defs);
    svg.append(mk('circle', { cx: 50, cy: 50, r: 42, fill: 'url(#doughG)', stroke: 'oklch(0.5 0.1 55)', 'stroke-width': 0.8 }));
    // Archimedean spiral of filling, centre outward.
    let d = '';
    for (let i = 0; i <= 120; i++) {
        const t = i / 120, r = 1.5 + 27 * t, a = t * 3 * 2 * Math.PI - Math.PI / 2;
        d += (i ? 'L' : 'M') + (50 + r * Math.cos(a)).toFixed(2) + ' ' + (50 + r * Math.sin(a)).toFixed(2);
    }
    svg.append(mk('path', { d, fill: 'none', stroke: 'oklch(0.88 0.17 150)', 'stroke-width': 4.2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }));
    [[30, 22, 2.2], [72, 25, 2.2], [82, 58, 2.2], [22, 60, 2.2], [55, 82, 2.2], [46, 16, 1.6]]
        .forEach(([cx, cy, r]) => svg.append(mk('circle', { cx, cy, r, fill: 'oklch(0.98 0.01 90)' })));
    svg.append(mk('circle', { cx: 50, cy: 50, r: 6.5, fill: 'url(#coreG)' }));
    svg.append(mk('circle', { cx: 47.5, cy: 47, r: 1.6, fill: 'oklch(0.99 0.04 150 / 0.9)' }));
    return h('div', { class: 'signet' }, svg);
}

function renderSignedResult(target, result) {
    clear(target);
    if (result.outcome === 'error') {
        target.append(notice('error', 'Signing failed: ' + result.message));
        return;
    }
    if (result.outcome !== 'bundle') return;

    const bundle = result.bundle;
    const approver = bundle.approver;
    const isCosign = result.action === 'cosign';
    const delegatedApproval = !isCosign && approver.operator_requires;
    const token = encodeToken(bundle);
    const name = approver.command.command || 'command';

    const facts = factRows([
        ['Signed by', result.signer],
        ['Timestamped', fmtTime(result.signed_at)],
        ['Command', name, true],
        ['Execution ID', approver.command.id, true],
        ['Target machines', (approver.command.target_machines || []).join(', '), true],
        isCosign ? ['Approved by', claimName(jwtClaims(approver.id_token))] : null,
        ['Who runs it', isCosign ? 'You, now — the co-signature is only valid briefly' : modeText(approver.operator_requires)],
    ]);

    const actions = h('div', { class: 'actions' },
        h('button', { class: 'btn', onclick: () => copyText(token, 'Signed token copied') }, icon('copy'), 'Copy token'),
        h('button', { class: 'btn', onclick: () => saveTokenFile(bundle) }, icon('download'), 'Save file'),
        h('span', { class: 'spacer' }),
        delegatedApproval ? null : h('button', {
            class: 'btn btn-primary',
            onclick: async (e) => {
                e.currentTarget.disabled = true;
                try {
                    await executeBundle(bundle);
                } catch (err) {
                    toast('Execution failed: ' + err.message, true);
                    e.currentTarget.disabled = false;
                }
            },
        }, icon('play'), 'Execute now'));

    target.append(h('section', { class: 'panel accent' },
        h('div', { class: 'sealed' },
            sealedSignet(),
            h('div', {},
                h('div', { class: 'sign-headline' }, isCosign ? 'Co-signed.' : 'Signed.'),
                facts)),
        delegatedApproval
            ? notice('', 'Send this token to the operator who will run it. They open it under "Sign a request" and co-sign it.')
            : null,
        h('div', { class: 'token-strip' },
            h('span', { class: 'lbl' }, 'token'),
            h('span', { class: 'val' }, token)),
        actions));
}

// ---------------------------------------------------------------------------
// Page: Commands
// ---------------------------------------------------------------------------

async function initCommandsPage() {
    const grid = $('cmd-grid');
    const filter = $('cmd-filter');
    const count = $('cmd-count');
    let commands;
    try {
        commands = await loadCommands();
    } catch (e) {
        grid.replaceWith(notice('error', 'Could not load commands: ' + e.message));
        return;
    }

    const render = () => {
        const q = filter.value.trim().toLowerCase();
        const shown = commands.filter(c =>
            !q || c.name.toLowerCase().includes(q) || (c.description || '').toLowerCase().includes(q));
        clear(grid);
        count.textContent = `${shown.length} of ${commands.length}`;
        if (commands.length === 0) {
            grid.append(h('div', { class: 'empty' }, 'No commands are configured in this signer\'s config.toml.'));
            return;
        }
        shown.forEach(cmd => grid.append(commandCard(cmd)));
    };
    filter.addEventListener('input', render);
    render();
}

function commandCard(cmd) {
    return h('button', { class: 'cmd-card', type: 'button', onclick: () => openSignModal(cmd) },
        h('div', { class: 'cmd-head' },
            h('div', { class: 'cmd-glyph' }, glyph(cmd.name)),
            h('div', {},
                h('div', { class: 'cmd-name' }, cmd.name),
                h('div', { class: 'cmd-desc' }, cmd.description || ''))),
        h('div', { class: 'cmd-meta' },
            h('span', { class: 'meta-pill', title: 'Self-execute: run within this long of signing' },
                icon('clock'), 'run within ' + fmtDuration(cmd.operator_max_validity_secs)),
            h('span', { class: 'meta-pill', title: 'Delegated: an approval stays usable this long' },
                icon('fingerprint'), 'delegate ' + fmtDuration(cmd.approver_max_validity_secs)),
            cmd.params.length
                ? h('span', { class: 'meta-pill' }, icon('params'),
                    cmd.params.length + (cmd.params.length === 1 ? ' parameter' : ' parameters'))
                : null),
        h('div', { class: 'cmd-foot' },
            h('span', { class: 'cmd-sign' }, icon('sign'), 'Prepare')));
}

const TARGETS_KEY = 'remonce.lastTargets';

function openSignModal(cmd) {
    const id = crypto.randomUUID();
    let delegated = false;
    let lastTargets = '';
    try { lastTargets = localStorage.getItem(TARGETS_KEY) || ''; } catch (_) { /* ignore */ }

    const targets = h('input', { id: 'f-targets', value: lastTargets, placeholder: 'agent hostnames, comma separated', spellcheck: 'false' });
    const notBefore = h('input', { id: 'f-nbf', type: 'datetime-local' });
    const notAfter = h('input', { id: 'f-naf', type: 'datetime-local' });
    const paramInputs = cmd.params.map(p => {
        const inputId = 'p-' + p.name;
        let input;
        if (p.allowed && p.allowed.length) {
            input = h('select', { id: inputId },
                (p.required || p.default) ? null : h('option', { value: '' }, ''),
                p.allowed.map(v => h('option', { value: v, selected: p.default === v }, v)));
        } else {
            const range = (p.min != null || p.max != null) ? `${p.min ?? ''}..${p.max ?? ''}` : '';
            input = h('input', { id: inputId, value: p.default || '', placeholder: range, spellcheck: 'false' });
        }
        return { p, input };
    });

    const reqRows = h('div', {});
    const addReqRow = () => {
        const row = h('div', { class: 'req-row' },
            h('input', { class: 'input req-claim', placeholder: 'claim, e.g. groups' }),
            h('select', { class: 'input req-op' },
                h('option', { value: 'contains' }, 'contains'),
                h('option', { value: 'equals' }, 'equals')),
            h('input', { class: 'input req-value', placeholder: 'value, e.g. noc-l2' }),
            h('button', { class: 'btn btn-ghost', type: 'button', title: 'Remove', onclick: () => { row.remove(); update(); } }, icon('close')));
        row.querySelectorAll('input, select').forEach(el => el.addEventListener('input', update));
        reqRows.append(row);
    };

    const modeHelp = h('p', { class: 'hint' });
    const delegateBox = h('div', { hidden: true },
        reqRows,
        h('button', { class: 'btn btn-sm', type: 'button', onclick: () => { addReqRow(); update(); } }, icon('plus'), 'Add requirement'));
    const selfBtn = h('button', { type: 'button', class: 'on' }, 'I\'ll run it');
    const delBtn = h('button', { type: 'button' }, 'Delegate');
    const setMode = (d) => {
        delegated = d;
        selfBtn.classList.toggle('on', !d);
        delBtn.classList.toggle('on', d);
        delegateBox.hidden = !d;
        modeHelp.textContent = d
            ? `Someone else co-signs and runs it, within ${fmtDuration(cmd.approver_max_validity_secs)} of your signature. ` +
              'Requirements restrict who may co-sign; with none, any operator may (policy still applies).'
            : `You run it yourself, within ${fmtDuration(cmd.operator_max_validity_secs)} of signing. It cannot be co-signed.`;
        update();
    };
    selfBtn.addEventListener('click', () => setMode(false));
    delBtn.addEventListener('click', () => setMode(true));

    const preview = h('pre', { class: 'code-block' });
    const error = h('div', { class: 'hint-line' });

    const build = () => {
        const command = { command: cmd.name, id };
        const t = targets.value.split(',').map(s => s.trim()).filter(Boolean);
        if (t.length) command.target_machines = t;
        const params = {};
        paramInputs.forEach(({ p, input }) => {
            const v = input.value.trim();
            if (v) params[p.name] = v;
        });
        if (Object.keys(params).length) command.params = params;
        if (notBefore.value) command.not_before = new Date(notBefore.value).toISOString();
        if (notAfter.value) command.not_after = new Date(notAfter.value).toISOString();
        let operator_requires = null;
        if (delegated) {
            const any_of = [];
            reqRows.querySelectorAll('.req-row').forEach(row => {
                const claim = row.querySelector('.req-claim').value.trim();
                const raw = row.querySelector('.req-value').value.trim();
                if (!claim || !raw) return;
                let value;
                try { value = JSON.parse(raw); } catch (_) { value = raw; }
                any_of.push({ op: row.querySelector('.req-op').value, claim, value });
            });
            operator_requires = { any_of };
        }
        return { command, operator_requires };
    };

    const problemsOf = ({ command }) => {
        const out = [];
        if (!command.target_machines) out.push('Add at least one target machine.');
        paramInputs.forEach(({ p, input }) => {
            if (p.required && !input.value.trim()) out.push(`Parameter '${p.name}' is required.`);
        });
        return out;
    };

    const signBtn = h('button', { class: 'btn btn-primary', type: 'button' }, icon('sign'), 'Sign');
    const copyBtn = h('button', { class: 'btn', type: 'button', title: 'Copy an unsigned request for someone else to review and sign' },
        icon('copy'), 'Copy request');
    const saveBtn = h('button', { class: 'btn', type: 'button', title: 'Save an unsigned request as a file for someone else to review and sign' },
        icon('download'), 'Save request');

    function update() {
        const draft = build();
        preview.textContent = signedPayloadText(draft.command, draft.operator_requires);
        const problems = problemsOf(draft);
        error.textContent = problems[0] || 'Signing asks you to log in again.';
        signBtn.disabled = problems.length > 0;
        copyBtn.disabled = problems.length > 0;
        saveBtn.disabled = problems.length > 0;
    }

    [targets, notBefore, notAfter, ...paramInputs.map(x => x.input)].forEach(el => {
        el.addEventListener('input', update);
        el.addEventListener('change', update);
    });

    copyBtn.addEventListener('click', () => {
        copyText(encodeToken(build()), 'Request copied — send it to whoever should sign it');
    });
    saveBtn.addEventListener('click', () => saveTokenFile(build()));
    signBtn.addEventListener('click', async () => {
        const draft = build();
        try { localStorage.setItem(TARGETS_KEY, targets.value.trim()); } catch (_) { /* ignore */ }
        signBtn.disabled = true;
        error.textContent = 'Redirecting to your identity provider…';
        try {
            await beginSigning({ action: 'approve', command: draft.command, operator_requires: draft.operator_requires });
        } catch (e) {
            error.textContent = 'Could not start signing: ' + e.message;
            signBtn.disabled = false;
        }
    });

    const close = () => { scrim.remove(); document.removeEventListener('keydown', onKey); };
    const onKey = (e) => { if (e.key === 'Escape') close(); };
    document.addEventListener('keydown', onKey);

    const scrim = h('div', { class: 'modal-scrim', onclick: (e) => { if (e.target === scrim) close(); } },
        h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Prepare ' + cmd.name },
            h('div', { class: 'modal-head' },
                h('div', {},
                    h('div', { class: 'modal-eyebrow' }, 'Prepare'),
                    h('div', { class: 'modal-title' }, 'Configure the signature')),
                h('button', { class: 'modal-close', type: 'button', title: 'Close', onclick: close }, icon('close'))),
            h('div', { class: 'modal-body' },
                h('div', { class: 'cmd-summary' },
                    h('div', { class: 'cmd-glyph' }, glyph(cmd.name)),
                    h('div', {},
                        h('div', { class: 'cmd-name' }, cmd.name),
                        h('div', { class: 'cmd-desc' }, cmd.description || ''))),
                h('div', { class: 'form-grid' },
                    h('div', { class: 'field full' },
                        h('label', { for: 'f-id' }, 'Execution ID', h('span', { class: 'hint' }, '· names the run and its log')),
                        h('input', { id: 'f-id', value: id, readonly: true })),
                    h('div', { class: 'field full' },
                        h('label', { for: 'f-targets' }, icon('target'), 'Target machines',
                            h('span', { class: 'hint' }, '· the agent checks its own hostname is listed')),
                        targets),
                    paramInputs.map(({ p, input }) => h('div', { class: 'field' },
                        h('label', { for: input.id }, p.name + (p.required ? ' *' : ''),
                            p.description ? h('span', { class: 'hint' }, '· ' + p.description) : null),
                        input))),
                h('div', { class: 'form-grid section' },
                    h('div', { class: 'field' },
                        h('label', { for: 'f-nbf' }, 'Not before', h('span', { class: 'hint' }, '· optional')),
                        notBefore),
                    h('div', { class: 'field' },
                        h('label', { for: 'f-naf' }, 'Not after', h('span', { class: 'hint' }, '· optional')),
                        notAfter)),
                h('div', { class: 'section' },
                    h('div', { class: 'label' }, 'Who runs it'),
                    h('div', { class: 'seg' }, selfBtn, delBtn),
                    modeHelp,
                    delegateBox),
                h('div', { class: 'code-head' },
                    h('span', { class: 'label' }, 'Signed payload'),
                    h('span', { class: 'hint' }, 'exactly what your signature covers')),
                preview),
            h('div', { class: 'modal-foot' },
                error,
                h('span', { class: 'spacer' }),
                h('button', { class: 'btn btn-ghost', type: 'button', onclick: close }, 'Cancel'),
                copyBtn,
                saveBtn,
                signBtn)));

    document.body.append(scrim);
    setMode(false);
    targets.focus();
}

// ---------------------------------------------------------------------------
// Page: Sign a request (review drafts, co-sign delegated approvals)
// ---------------------------------------------------------------------------

async function initReviewPage() {
    const input = $('review-token');
    const detail = $('review-detail');
    const result = await takeSignResult();
    if (result) renderSignedResult($('review-result'), result);

    const show = async () => {
        clear(detail);
        detail.hidden = false;
        let parsed;
        try {
            parsed = classifyToken(decodeToken(input.value));
        } catch (e) {
            detail.append(notice('error', e.message));
            return;
        }
        if (parsed.kind === 'draft') await renderDraftReview(detail, parsed);
        else await renderApprovalReview(detail, parsed.bundle);
    };
    $('review-btn').addEventListener('click', show);
    acceptTokens(input, $('review-file'), $('review-file-input'), $('review-input'), show);

    // A link or another page may prefill a request; nothing is signed
    // without a click.
    const prefill = takeHandOff() || new URLSearchParams(window.location.search).get('token');
    if (prefill) {
        input.value = prefill;
        show();
    }
}

async function renderDraftReview(target, draft) {
    const { problems, info } = await requestProblems(draft.command);
    const signBtn = h('button', { class: 'btn btn-primary', disabled: problems.length > 0 }, icon('sign'), 'Sign');
    const status = h('span', { class: 'hint-line' }, 'Signing asks you to log in again, and uses a one-time key.');
    signBtn.addEventListener('click', async () => {
        signBtn.disabled = true;
        status.textContent = 'Redirecting to your identity provider…';
        try {
            await beginSigning({ action: 'approve', command: draft.command, operator_requires: draft.operator_requires });
        } catch (e) {
            status.textContent = 'Could not start signing: ' + e.message;
            signBtn.disabled = false;
        }
    });

    target.append(h('section', { class: 'panel accent' },
        panelTitle(draft.command.command, info && info.description),
        problems.map(p => notice('error', p)),
        factRows(commandFacts(draft.command, draft.operator_requires)),
        h('div', { class: 'code-head' },
            h('span', { class: 'label' }, 'Signed payload'),
            h('span', { class: 'hint' }, 'exactly what your signature covers')),
        h('pre', { class: 'code-block' }, signedPayloadText(draft.command, draft.operator_requires)),
        h('div', { class: 'actions' }, status, h('span', { class: 'spacer' }), signBtn)));
}

async function renderApprovalReview(target, bundle) {
    const approver = bundle.approver;
    const info = await commandInfo(approver.command.command);
    const panel = h('section', { class: 'panel accent' },
        panelTitle(approver.command.command, info && info.description));

    if (bundle.operator) {
        panel.append(notice('', 'This approval is already co-signed. Run it from Execute.'));
    } else if (!approver.operator_requires) {
        panel.append(notice('', 'This approval is self-execute only, so it can\'t be co-signed. ' +
            'The approver runs it from Execute.'));
    } else {
        panel.append(notice('warn', 'Co-signing runs this command with your identity as the operator. ' +
            'Check what was approved and who approved it.'));
    }

    panel.append(factRows([
        ...commandFacts(approver.command, approver.operator_requires),
        ...bundleSignerRows(bundle),
    ]));
    panel.append(h('p', { class: 'hint' },
        'Identities are read from the tokens in the bundle; the agent verifies them before running anything.'));

    const actions = h('div', { class: 'actions' });
    if (bundle.operator || !approver.operator_requires) {
        actions.append(h('span', { class: 'spacer' }),
            h('button', { class: 'btn', onclick: () => handOff('/ui/execute', bundle) }, icon('play'), 'Open in Execute'));
    } else {
        const status = h('span', { class: 'hint-line' }, 'Co-signing asks you to log in again. Execute promptly afterwards.');
        const btn = h('button', { class: 'btn btn-primary' }, icon('fingerprint'), 'Co-sign');
        btn.addEventListener('click', async () => {
            btn.disabled = true;
            status.textContent = 'Redirecting to your identity provider…';
            try {
                await beginSigning({ action: 'cosign', approver });
            } catch (e) {
                status.textContent = 'Could not start co-signing: ' + e.message;
                btn.disabled = false;
            }
        });
        actions.append(status, h('span', { class: 'spacer' }), btn);
    }
    panel.append(actions);
    target.append(panel);
}

// ---------------------------------------------------------------------------
// Page: Execute (and revoke)
// ---------------------------------------------------------------------------

async function initExecutePage() {
    const input = $('exec-token');
    const detail = $('exec-detail');
    const resultBox = $('exec-result');

    const result = await takeSignResult();
    if (result && result.outcome === 'revoked') {
        const ok = result.status >= 200 && result.status < 300;
        resultBox.append(ok
            ? notice('ok', (result.body && result.body.message) || 'Approval revoked.')
            : notice('error', `Revocation refused (${result.status}): ` +
                ((result.body && result.body.error) || JSON.stringify(result.body))));
    } else if (result && result.outcome === 'error') {
        resultBox.append(notice('error', 'Revocation failed: ' + result.message));
    }

    const show = async () => {
        clear(detail);
        detail.hidden = false;
        let parsed;
        try {
            parsed = classifyToken(decodeToken(input.value));
        } catch (e) {
            detail.append(notice('error', e.message));
            return;
        }
        if (parsed.kind === 'draft') {
            const draft = { command: parsed.command, operator_requires: parsed.operator_requires };
            detail.append(h('section', { class: 'panel' },
                notice('warn', 'This is an unsigned request, so there is nothing to run yet. Review and sign it first.'),
                h('div', { class: 'actions' },
                    h('span', { class: 'spacer' }),
                    h('button', { class: 'btn btn-primary', onclick: () => handOff('/ui/review', draft) },
                        icon('fingerprint'), 'Open in Sign a request'))));
            return;
        }
        await renderExecuteDetail(detail, parsed.bundle);
    };
    $('exec-btn').addEventListener('click', show);
    acceptTokens(input, $('exec-file'), $('exec-file-input'), $('exec-input'), show);

    const handed = takeHandOff();
    const legacy = new URLSearchParams(window.location.search).get('signed_token');
    if (handed || legacy) {
        input.value = handed || legacy;
        show();
    }
}

async function renderExecuteDetail(target, bundle) {
    const approver = bundle.approver;
    const info = await commandInfo(approver.command.command);
    const needsCosign = approver.operator_requires && !bundle.operator;
    const panel = h('section', { class: 'panel accent' },
        panelTitle(approver.command.command, info && info.description));
    if (needsCosign) {
        panel.append(notice('warn', 'This approval is delegated and needs a co-signature before it can run. ' +
            'Open it under "Sign a request".'));
    }
    panel.append(factRows([
        ...commandFacts(approver.command, approver.operator_requires),
        ...bundleSignerRows(bundle),
    ]));

    const status = h('span', { class: 'hint-line' }, 'Runs on the agent selected at the top.');
    const execBtn = h('button', { class: 'btn btn-primary', disabled: needsCosign }, icon('play'), 'Execute');
    execBtn.addEventListener('click', async () => {
        execBtn.disabled = true;
        status.textContent = 'Submitting to ' + (agentUrl() || 'the default agent') + '…';
        try {
            await executeBundle(bundle);
        } catch (e) {
            status.textContent = 'The agent refused: ' + e.message;
            execBtn.disabled = false;
        }
    });
    const revokeBtn = h('button', { class: 'btn btn-danger', title: 'Anyone may revoke their own approval; revoking someone else\'s needs policy approval' },
        icon('revoke'), 'Revoke approval');
    revokeBtn.addEventListener('click', async () => {
        const agent = agentUrl() || 'the default agent';
        if (!confirm(`Revoke this approval of '${approver.command.command}' on ${agent}? ` +
            'You will be asked to log in again. This cannot be undone.')) return;
        revokeBtn.disabled = true;
        status.textContent = 'Redirecting to your identity provider…';
        try {
            await beginSigning({ action: 'revoke', approver, agent_url: agentUrl() });
        } catch (e) {
            status.textContent = 'Could not start revocation: ' + e.message;
            revokeBtn.disabled = false;
        }
    });
    panel.append(h('div', { class: 'actions' }, status, h('span', { class: 'spacer' }), revokeBtn, execBtn));
    target.append(panel);
}

// ---------------------------------------------------------------------------
// Page: Runs (execution logs and files, streamed from the agent)
// ---------------------------------------------------------------------------

function initMonitorPage() {
    const params = new URLSearchParams(window.location.search);
    const id = params.get('id');
    const path = params.get('path');
    const name = params.get('name');
    if (params.get('agent_url')) $('agent-url').value = params.get('agent_url');

    if (!id && !path && !name) {
        $('monitor-open').hidden = false;
        const go = () => {
            const v = $('monitor-id').value.trim();
            if (!v) return;
            const p = new URLSearchParams({ id: v });
            if (agentUrl()) p.set('agent_url', agentUrl());
            window.location.assign('/ui/monitor?' + p.toString());
        };
        $('monitor-go').addEventListener('click', go);
        $('monitor-id').addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
        return;
    }

    $('monitor-view').hidden = false;
    const isRun = Boolean(id);
    const tail = params.get('tail_lines') || (isRun ? null : '1000');
    const pill = $('run-state');
    const out = $('term-out');
    const facts = $('run-facts');
    const filter = $('term-filter');
    const shown = $('term-count');
    let follow = true;
    let wrap = true;
    const lines = [];
    let partial = '';
    let inHeader = false;
    let finished = false;

    const setState = (state, label) => {
        pill.dataset.state = state;
        pill.lastChild.textContent = label || state;
    };

    const factMap = new Map();
    const setFact = (k, v) => {
        let el = factMap.get(k);
        if (!el) {
            el = h('span', { class: 'v' });
            facts.append(h('div', { class: 'run-fact' }, h('span', { class: 'k' }, k), el));
            factMap.set(k, el);
        }
        el.textContent = v;
        el.title = v;
    };

    $('run-title').textContent = isRun ? 'Run ' + id.slice(0, 8) : (name || displayPath(path).split(/[\\/]/).pop());
    $('term-title').textContent = isRun ? 'execution log · ' + id : (name || displayPath(path));
    setFact(isRun ? 'Execution ID' : 'File', isRun ? id : (name || displayPath(path)));
    setFact('Agent', agentUrl() || 'default');
    if (!isRun) setFact('Showing', tail === '-1' ? 'whole file' : `last ${tail} lines, then new lines`);

    const matches = (text) => {
        const q = filter.value.trim().toLowerCase();
        return !q || text.toLowerCase().includes(q);
    };
    const renderMsg = (el, text) => {
        clear(el);
        const q = filter.value.trim();
        if (!q) { el.textContent = text; return; }
        const lower = text.toLowerCase(), ql = q.toLowerCase();
        let i = 0, j;
        while ((j = lower.indexOf(ql, i)) !== -1) {
            el.append(text.slice(i, j), h('mark', {}, text.slice(j, j + q.length)));
            i = j + q.length;
        }
        el.append(text.slice(i));
    };
    const updateCount = () => {
        const visible = lines.filter(l => !l.el.classList.contains('hidden')).length;
        shown.textContent = `${visible.toLocaleString()} of ${lines.length.toLocaleString()} lines`;
    };

    // The agent writes a header block before the command's output and a
    // trailer when it ends; both are real facts about the run.
    const classify = (text, row) => {
        if (!isRun) return;
        if (text === '--- EXECUTION LOG ---') { inHeader = true; row.classList.add('meta'); return; }
        if (inHeader) {
            row.classList.add('meta');
            if (/^-+$/.test(text)) { inHeader = false; return; }
            const m = text.match(/^(ID|User|Time|Command|Executable): (.*)$/);
            if (m) {
                const label = { ID: null, User: 'Approved by', Time: 'Approved at', Command: 'Command', Executable: 'Executable' }[m[1]];
                if (label) setFact(label, m[1] === 'Time' ? fmtTime(m[2]) : m[2]);
            }
            return;
        }
        const exit = text.match(/^--- (EXIT|TIMEOUT|WAIT ERROR)(?::\s*(.*))? ---$/);
        if (exit) {
            finished = true;
            const code = exit[2] && exit[2].match(/-?\d+/);
            const ok = exit[1] === 'EXIT' && code && code[0] === '0';
            row.classList.add(ok ? 'exit-ok' : 'exit-bad');
            if (exit[1] === 'TIMEOUT') { setFact('Result', 'killed: timed out'); setState('failed', 'timed out'); }
            else if (exit[1] === 'WAIT ERROR') { setFact('Result', exit[2] || 'wait error'); setState('failed', 'error'); }
            else { setFact('Result', 'exit ' + (code ? code[0] : exit[2])); setState(ok ? 'finished' : 'failed', ok ? 'finished' : 'failed'); }
        }
    };

    const addLine = (text) => {
        const msg = h('span', { class: 'log-msg' });
        const row = h('div', { class: 'log-line' }, h('span', { class: 'log-n' }, lines.length + 1), msg);
        classify(text, row);
        renderMsg(msg, text);
        if (!matches(text)) row.classList.add('hidden');
        lines.push({ text, el: row, msg });
        out.append(row);
    };

    const ingest = (chunk) => {
        const parts = (partial + chunk).split(/\r?\n/);
        partial = parts.pop();
        parts.forEach(addLine);
        updateCount();
        if (follow) out.scrollTop = out.scrollHeight;
    };

    filter.addEventListener('input', () => {
        lines.forEach(l => {
            l.el.classList.toggle('hidden', !matches(l.text));
            renderMsg(l.msg, l.text);
        });
        updateCount();
    });
    const wrapBtn = $('term-wrap'), followBtn = $('term-follow');
    wrapBtn.addEventListener('click', () => {
        wrap = !wrap;
        wrapBtn.classList.toggle('on', wrap);
        out.classList.toggle('wrap', wrap);
    });
    followBtn.addEventListener('click', () => {
        follow = !follow;
        followBtn.classList.toggle('on', follow);
        if (follow) out.scrollTop = out.scrollHeight;
    });
    const allText = () => lines.map(l => l.text).concat(partial ? [partial] : []).join('\n');
    $('term-copy').addEventListener('click', () => copyText(allText(), 'Log copied'));
    $('term-download').addEventListener('click', () => {
        const url = URL.createObjectURL(new Blob([allText()], { type: 'text/plain' }));
        const a = h('a', { href: url, download: (isRun ? id : (name || 'file')) + '.log' });
        document.body.append(a); a.click(); a.remove();
        URL.revokeObjectURL(url);
    });
    if (!isRun) {
        const range = $('term-range');
        range.hidden = false;
        range.querySelectorAll('button').forEach(b => {
            b.classList.toggle('on', b.dataset.tail === tail);
            b.addEventListener('click', () => {
                params.set('tail_lines', b.dataset.tail);
                window.location.search = params.toString();
            });
        });
    }

    const ws = new URLSearchParams();
    if (agentUrl()) ws.set('agent_url', agentUrl());
    if (isRun) ws.set('id', id);
    if (name) ws.set('name', name);
    if (path) ws.set('path', path);
    if (tail) ws.set('tail_lines', tail);
    const socket = new WebSocket(
        window.location.origin.replace(/^http/, 'ws') + (isRun ? '/ws/exec?' : '/ws/file?') + ws.toString());
    setState('connecting');
    socket.onopen = () => setState('streaming');
    socket.onmessage = (e) => {
        if (typeof e.data === 'string') ingest(e.data);
    };
    socket.onerror = () => { if (!finished) setState('error', 'connection error'); };
    socket.onclose = () => {
        if (partial) { addLine(partial); partial = ''; updateCount(); }
        if (!finished && pill.dataset.state !== 'error') setState('closed', 'disconnected');
    };
}

// ---------------------------------------------------------------------------
// Page: Files
// ---------------------------------------------------------------------------

async function initFilesPage() {
    const grid = $('files-grid');
    const load = async () => {
        clear(grid).append(h('div', { class: 'empty' }, 'Loading…'));
        let files;
        try {
            const p = new URLSearchParams();
            if (agentUrl()) p.set('agent_url', agentUrl());
            const res = await fetch('/api/agent/files?' + p.toString());
            if (res.status === 401) throw new Error('The agent rejected your session — log in again (/auth/login).');
            if (!res.ok) throw new Error(await errorText(res));
            files = await res.json();
        } catch (e) {
            clear(grid).append(notice('error', 'Could not list files: ' + e.message));
            return;
        }
        clear(grid);
        if (files.length === 0) {
            grid.append(h('div', { class: 'empty' }, 'The agent exposes no files.'));
            return;
        }
        const groups = new Map();
        files.forEach(f => {
            const key = f.name || f.path;
            if (!groups.has(key)) groups.set(key, { name: f.name, desc: f.description, paths: [] });
            groups.get(key).paths.push(f.path);
        });
        [...groups.keys()].sort().forEach(key => grid.append(fileCard(groups.get(key))));
    };
    $('files-refresh').addEventListener('click', load);
    $('agent-url').addEventListener('change', load);
    load();
}

function fileCard(g) {
    const open = (path) => {
        const p = new URLSearchParams({ path });
        if (agentUrl()) p.set('agent_url', agentUrl());
        window.location.assign('/ui/monitor?' + p.toString());
    };
    const title = g.name || displayPath(g.paths[0]).split(/[\\/]/).pop();
    let chooser;
    if (g.paths.length > 1) {
        chooser = h('select', { class: 'input' },
            g.paths.map(p => h('option', { value: p, title: p }, p.split(/[\\/]/).pop())));
    }
    return h('div', { class: 'cmd-card' },
        h('div', { class: 'cmd-head' },
            h('div', { class: 'cmd-glyph' }, icon('file')),
            h('div', {},
                h('div', { class: 'cmd-name' }, title),
                h('div', { class: 'cmd-desc' }, g.desc || ''))),
        chooser || h('div', { class: 'meta-pill', title: displayPath(g.paths[0]) }, displayPath(g.paths[0])),
        h('div', { class: 'cmd-foot' },
            h('button', { class: 'btn btn-sm', onclick: () => open(chooser ? chooser.value : g.paths[0]) },
                icon('terminal'), g.paths.length > 1 ? `View (${g.paths.length} files)` : 'View')));
}

// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
    const page = document.body.dataset.page;
    document.querySelectorAll('[data-nav]').forEach(a => {
        a.classList.toggle('active', a.dataset.nav === page);
    });
    initAgentField();
    const init = {
        commands: initCommandsPage,
        review: initReviewPage,
        execute: initExecutePage,
        monitor: initMonitorPage,
        files: initFilesPage,
    }[page];
    if (init) Promise.resolve(init()).catch(e => toast(e.message, true));
});
