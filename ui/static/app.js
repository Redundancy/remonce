// Remonce local signer UI.
//
// Every value shown comes from the selected agent (its command catalog via
// /api/agent/commands, or its log stream), from a request file the user
// opened, or from a signing result. Values decoded client-side from a
// request are what it *claims*, and requirement matching here is for display;
// the agent verifies every approval and its policy decides.
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
// request (no approvals yet) or approval (one or more). The content is the
// same JSON the CLI reads (`remonce approve|submit|revoke --bundle FILE`).
function tokenFileName(req) {
    const name = String(req.command.command || 'command').replace(/[^A-Za-z0-9._-]+/g, '_');
    const id = String(req.command.id || '').replace(/[^A-Za-z0-9]/g, '').slice(0, 8);
    const kind = req.approvals.length ? 'approval' : 'request';
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
// Request files: JSON (base64 accepted for pages handing over)
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

// A request file: { command: {…}, approvals: […] }, or a bare command
// ({ command: "name", id, … }) as a request with no approvals yet.
function parseRequest(obj) {
    if (obj && typeof obj === 'object' && (obj.approver || obj.signature || 'operator_requires' in obj)) {
        throw new Error('This file was made by an older version of Remonce (approver/operator bundles). ' +
            'Ask for the request to be prepared again.');
    }
    if (obj && typeof obj.command === 'string') return { command: obj, approvals: [] };
    if (obj && obj.command && typeof obj.command === 'object' && !Array.isArray(obj.command)) {
        const approvals = obj.approvals === undefined ? [] : obj.approvals;
        if (!Array.isArray(approvals)) throw new Error('Not a Remonce request: approvals must be a list');
        return { command: obj.command, approvals };
    }
    throw new Error('Not a Remonce request');
}

function requestJson(req) {
    return JSON.stringify({ command: req.command, approvals: req.approvals }, null, 2);
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

// What every approval signs: {command, remonce: "request/v2"} with sorted
// keys (sent compact; shown indented).
function signedPayloadText(command) {
    return JSON.stringify(sortKeys({ command, remonce: 'request/v2' }), null, 2);
}

// ---------------------------------------------------------------------------
// Agent selection and API calls
// ---------------------------------------------------------------------------

const AGENT_KEY = 'remonce.agentUrl';

function agentUrl() {
    const select = $('agent-url');
    return select ? select.value : '';
}

function agentOption() {
    const select = $('agent-url');
    return (select && select.selectedOptions[0]) || null;
}

// The signer reaches agents from its own process, so a localhost agent is
// the one on the machine running the signer — not the one running this
// browser. The signer marks those options data-local="true".
function agentIsLocal() {
    const o = agentOption();
    return Boolean(o && o.dataset.local === 'true');
}

// The selected agent, for use in a sentence.
function agentDisplay() {
    const o = agentOption();
    if (!o) return 'the default agent';
    if (o.dataset.local === 'true') return `this machine (${document.body.dataset.signerHost})`;
    return o.dataset.name || o.value.replace(/^https:\/\//, '');
}

function showAgentKind() {
    const local = agentIsLocal();
    $('agent-field').classList.toggle('is-local', local);
    $('agent-local').hidden = !local;
}

function originOf(raw) {
    try { return new URL(raw).origin; } catch (_) { return null; }
}

// Select the agent at `raw` without remembering it (for links that name an
// agent). One the signer doesn't know is shown as such; requests to it are
// refused.
function setAgent(raw) {
    const select = $('agent-url');
    const origin = originOf(raw);
    if (!select || !origin) return;
    let option = [...select.options].find(o => o.value === origin);
    if (!option) {
        option = h('option', { value: origin }, 'not configured — ' + origin.replace(/^https:\/\//, ''));
        select.append(option);
    }
    select.value = origin;
    showAgentKind();
}

function initAgentField() {
    const select = $('agent-url');
    if (!select) return;
    let stored = null;
    try { stored = localStorage.getItem(AGENT_KEY); } catch (_) { /* storage blocked */ }
    const origin = stored && originOf(stored);
    if (origin && [...select.options].some(o => o.value === origin)) select.value = origin;
    select.addEventListener('change', () => {
        showAgentKind();
        try { localStorage.setItem(AGENT_KEY, select.value); } catch (_) { /* ignore */ }
    });
    showAgentKind();
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

// The selected agent's catalog: what can be requested there and what each
// command needs. Cached per agent for the life of the page.
const catalogs = new Map();
function loadCatalog() {
    const key = agentUrl();
    if (!catalogs.has(key)) {
        const p = new URLSearchParams();
        if (key) p.set('agent_url', key);
        const promise = fetch('/api/agent/commands?' + p.toString()).then(async (res) => {
            if (res.status === 401) throw new Error('The agent rejected your session — log in again (/auth/login).');
            if (!res.ok) throw new Error(await errorText(res));
            return res.json();
        });
        promise.catch(() => catalogs.delete(key));
        catalogs.set(key, promise);
    }
    return catalogs.get(key);
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
// Requirements, as the agent publishes them from policy. Matching here is
// for display only: the agent verifies every approval and policy decides.
// ---------------------------------------------------------------------------

function sameJson(a, b) {
    return JSON.stringify(a) === JSON.stringify(b);
}

function claimMatches(p, claims) {
    const v = claims ? claims[p.claim] : undefined;
    if (p.op === 'equals') return v !== undefined && sameJson(v, p.value);
    if (p.op === 'contains') return Array.isArray(v) && v.some(x => sameJson(x, p.value));
    return false;
}

// "any_of": [] means anyone; a slot without it accepts no one.
function slotAccepts(slot, claims) {
    if (!slot || !Array.isArray(slot.any_of)) return false;
    return slot.any_of.length === 0 || slot.any_of.some(p => claimMatches(p, claims));
}

function slotText(slot) {
    if (!slot || !Array.isArray(slot.any_of)) return 'no one';
    if (slot.description) return slot.description;
    return slot.any_of.length === 0 ? 'anyone' : slot.any_of.map(fmtPredicate).join(' or ');
}

// An agent never runs a request without at least one approval.
function effectiveSlots(r) {
    return r.approvals.length ? r.approvals : [{ description: 'anyone', any_of: [] }];
}

// Give each slot its own approver where possible (augmenting paths, so a
// fit is found whenever one exists). Free approvers are tried before
// reassigning a taken one, so slots fill in approval order where they can.
// Returns, per slot, an approver index or -1.
function matchSlots(slots, approvers) {
    const slotOf = approvers.map(() => -1);
    const assign = (s, seen) => {
        const order = approvers.map((_, i) => i).sort((a, b) => (slotOf[a] !== -1) - (slotOf[b] !== -1));
        for (const i of order) {
            if (seen.has(i) || !slotAccepts(slots[s], approvers[i].claims)) continue;
            seen.add(i);
            if (slotOf[i] === -1 || assign(slotOf[i], seen)) {
                slotOf[i] = s;
                return true;
            }
        }
        return false;
    };
    slots.forEach((_, s) => assign(s, new Set()));
    const bySlot = slots.map(() => -1);
    slotOf.forEach((s, i) => { if (s !== -1) bySlot[s] = i; });
    return bySlot;
}

function requirementSummary(info) {
    if (info.requirements_error) return 'Published requirements are unreadable';
    const r = info.requirements;
    if (!r) return 'No published requirements';
    const needs = effectiveSlots(r).map(slotText).join(' + ');
    return `Needs ${needs} · run by ${slotText(r.executors)}` + (r.additional_policy ? ' · plus further policy' : '');
}

// What a request's approvals claim, checked against the catalog entry
// (`info`, may be null): which have expired, repeat a person, and which
// requirement slots they fill.
function requestStatus(req, info) {
    const now = Date.now() / 1000;
    const seen = new Set();
    const approvers = req.approvals.map((a) => {
        const claims = jwtClaims(a.id_token) || {};
        const x = { name: claimName(claims), claims, iat: claims.iat };
        x.expired = Boolean(info && claims.iat && now - claims.iat > info.approval_validity_secs);
        x.duplicate = Boolean(claims.sub && seen.has(claims.sub));
        if (claims.sub) seen.add(claims.sub);
        return x;
    });
    const live = approvers.filter(a => !a.expired && !a.duplicate);
    const r = info && info.requirements;
    if (!r) return { approvers, live, slots: null, bySlot: null, complete: null };
    const slots = effectiveSlots(r);
    const bySlot = matchSlots(slots, live);
    return { approvers, live, slots, bySlot, complete: bySlot.every(i => i !== -1) };
}

function tag(kind, ...content) {
    return h('span', { class: 'tag' + (kind ? ' ' + kind : '') }, ...content);
}

function approvalFacts(st) {
    if (st.approvers.length === 0) return [['Approvals', null]];
    return st.approvers.map((a, i) => {
        const notes = [];
        if (a.iat) notes.push('logged in ' + fmtTime(a.iat * 1000));
        if (Array.isArray(a.claims.groups)) notes.push('groups: ' + a.claims.groups.join(', '));
        return ['Approval ' + (i + 1), h('span', {},
            a.name,
            notes.length ? h('span', { class: 'muted' }, '  ·  ' + notes.join('  ·  ')) : null,
            a.expired ? tag('bad', 'expired') : null,
            a.duplicate ? tag('bad', 'same person again') : null)];
    });
}

// The command's published requirements; with a status, which are met.
function requirementFacts(info, st) {
    if (!info) return [];
    if (info.requirements_error) return [['Requirements', 'Published, but unreadable: ' + info.requirements_error]];
    const r = info.requirements;
    if (!r) return [['Requirements', 'None published for this command; the agent\'s policy decides']];
    const rows = [];
    if (r.description) rows.push(['Requirements', r.description]);
    effectiveSlots(r).forEach((slot, j) => {
        const i = st ? st.bySlot[j] : -1;
        rows.push(['Approver ' + (j + 1), h('span', {}, slotText(slot),
            st ? (i >= 0 ? tag('ok', icon('check'), st.live[i].name) : tag('', 'waiting')) : null)]);
    });
    rows.push(['Run by', slotText(r.executors)]);
    if (r.additional_policy) rows.push(['Further policy', r.additional_policy]);
    rows.push(['Approvals valid', fmtDuration(info.approval_validity_secs) + ' after each approver logs in']);
    return rows;
}

function missingText(st) {
    return st.slots.filter((_, j) => st.bySlot[j] === -1).map(slotText).join(' + ');
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

function commandFacts(command) {
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
    ];
}

function panelTitle(name, description) {
    return h('div', { class: 'panel-title' },
        h('div', { class: 'cmd-glyph' }, glyph(name)),
        h('div', { class: 'text' },
            h('div', { class: 'n' }, name),
            description ? h('div', { class: 'd' }, description) : null));
}

// What the page can tell without asking the agent to run anything:
// problems it will certainly reject, and warnings worth a look.
async function requestContext(command) {
    const problems = [];
    const warnings = [];
    const targets = Array.isArray(command.target_machines) ? command.target_machines : [];
    if (targets.length === 0) {
        problems.push('No target machines. Agents refuse requests without target_machines.');
    }
    let info = null;
    try {
        const catalog = await loadCatalog();
        info = catalog.commands.find(c => c.name === command.command) || null;
        if (!info) {
            warnings.push(`The selected agent (${catalog.host}) doesn't offer '${command.command}'. ` +
                'Select the agent this request is for at the top.');
        } else if (targets.length && !targets.includes(catalog.host)) {
            warnings.push(`The selected agent (${catalog.host}) isn't one of the target machines, so it will refuse this request.`);
        }
    } catch (e) {
        warnings.push('Could not load the selected agent\'s commands: ' + e.message);
    }
    return { problems, warnings, info };
}

// Expired or repeated approvals make the agent refuse the whole request;
// offer to drop them.
function staleApprovalsNotice(req, st, rerender) {
    const bad = st.approvers.filter(a => a.expired || a.duplicate).length;
    if (!bad) return null;
    const keep = req.approvals.filter((_, i) => !st.approvers[i].expired && !st.approvers[i].duplicate);
    return notice('warn',
        `${bad === 1 ? 'One approval has' : bad + ' approvals have'} expired or repeat a person, ` +
        'so the agent will refuse this request as it is. ',
        h('button', { class: 'btn btn-sm', type: 'button', onclick: () => rerender({ command: req.command, approvals: keep }) },
            'Remove ' + (bad === 1 ? 'it' : 'them')));
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

async function renderSignedResult(target, result) {
    clear(target);
    if (result.outcome === 'error') {
        target.append(notice('error', 'Signing failed: ' + result.message));
        return;
    }
    if (result.outcome !== 'bundle') return;

    const req = result.bundle;
    const { info } = await requestContext(req.command);
    const st = requestStatus(req, info);
    const counted = st.slots
        ? `${st.bySlot.filter(i => i >= 0).length} of ${st.slots.length} needed`
        : `${req.approvals.length}; the agent's policy decides whether that is enough`;

    const facts = factRows([
        ['Approved by', result.signer],
        ['Timestamped', fmtTime(result.signed_at)],
        ['Command', req.command.command, true],
        ['Execution ID', req.command.id, true],
        ['Request', result.request_id, true],
        ['Approvals', counted],
    ]);

    const execBtn = h('button', {
        class: 'btn btn-primary',
        onclick: async (e) => {
            e.currentTarget.disabled = true;
            try {
                await executeBundle(req);
            } catch (err) {
                toast('Execution failed: ' + err.message, true);
                e.currentTarget.disabled = false;
            }
        },
    }, icon('play'), 'Execute now');

    target.append(h('section', { class: 'panel accent' },
        h('div', { class: 'sealed' },
            sealedSignet(),
            h('div', {},
                h('div', { class: 'sign-headline' }, 'Approved.'),
                facts)),
        st.complete === false
            ? notice('', `Still needs ${missingText(st)}. Save the file and send it to the next approver; ` +
                'they open it under "Sign a request".')
            : null,
        h('div', { class: 'actions' },
            h('button', { class: 'btn', onclick: () => copyText(requestJson(req), 'Request copied') }, icon('copy'), 'Copy'),
            h('button', { class: 'btn', onclick: () => saveTokenFile(req) }, icon('download'), 'Save file'),
            h('span', { class: 'spacer' }),
            st.complete === false ? null : execBtn)));
}

// ---------------------------------------------------------------------------
// Page: Commands
// ---------------------------------------------------------------------------

async function initCommandsPage() {
    const grid = $('cmd-grid');
    const filter = $('cmd-filter');
    const count = $('cmd-count');
    let catalog = null;

    const render = () => {
        const commands = catalog.commands;
        const q = filter.value.trim().toLowerCase();
        const shown = commands.filter(c =>
            !q || c.name.toLowerCase().includes(q) || (c.description || '').toLowerCase().includes(q));
        clear(grid);
        count.textContent = `${shown.length} of ${commands.length} on ${catalog.host}`;
        if (commands.length === 0) {
            grid.append(h('div', { class: 'empty' }, `The agent on ${catalog.host} offers no commands.`));
            return;
        }
        shown.forEach(cmd => grid.append(commandCard(cmd, catalog.host)));
    };
    const load = async () => {
        count.textContent = '';
        clear(grid).append(h('div', { class: 'empty' }, 'Loading…'));
        try {
            catalog = await loadCatalog();
        } catch (e) {
            catalog = null;
            clear(grid).append(notice('error', 'Could not load the agent\'s commands: ' + e.message));
            return;
        }
        render();
    };
    filter.addEventListener('input', () => { if (catalog) render(); });
    $('agent-url').addEventListener('change', load);
    load();
}

function commandCard(cmd, host) {
    return h('button', { class: 'cmd-card', type: 'button', onclick: () => openSignModal(cmd, host) },
        h('div', { class: 'cmd-head' },
            h('div', { class: 'cmd-glyph' }, glyph(cmd.name)),
            h('div', {},
                h('div', { class: 'cmd-name' }, cmd.name),
                h('div', { class: 'cmd-desc' }, cmd.description || ''))),
        h('div', { class: 'cmd-req' }, requirementSummary(cmd)),
        h('div', { class: 'cmd-meta' },
            h('span', { class: 'meta-pill', title: 'Each approval stays usable this long after the approver logs in' },
                icon('clock'), 'approvals valid ' + fmtDuration(cmd.approval_validity_secs)),
            cmd.params.length
                ? h('span', { class: 'meta-pill' }, icon('params'),
                    cmd.params.length + (cmd.params.length === 1 ? ' parameter' : ' parameters'))
                : null),
        h('div', { class: 'cmd-foot' },
            h('span', { class: 'cmd-sign' }, icon('sign'), 'Prepare')));
}

function openSignModal(cmd, host) {
    const id = crypto.randomUUID();

    const targets = h('input', { id: 'f-targets', value: host || '', placeholder: 'agent hostnames, comma separated', spellcheck: 'false' });
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
        return { command, approvals: [] };
    };

    const problemsOf = ({ command }) => {
        const out = [];
        if (!command.target_machines) out.push('Add at least one target machine.');
        paramInputs.forEach(({ p, input }) => {
            if (p.required && !input.value.trim()) out.push(`Parameter '${p.name}' is required.`);
        });
        return out;
    };

    const signBtn = h('button', { class: 'btn btn-primary', type: 'button' }, icon('sign'), 'Approve');
    const copyBtn = h('button', { class: 'btn', type: 'button', title: 'Copy the request for someone else to approve' },
        icon('copy'), 'Copy request');
    const saveBtn = h('button', { class: 'btn', type: 'button', title: 'Save the request as a file for someone else to approve' },
        icon('download'), 'Save request');

    function update() {
        const req = build();
        preview.textContent = signedPayloadText(req.command);
        const problems = problemsOf(req);
        error.textContent = problems[0] || 'Approving asks you to log in again.';
        signBtn.disabled = problems.length > 0;
        copyBtn.disabled = problems.length > 0;
        saveBtn.disabled = problems.length > 0;
    }

    [targets, notBefore, notAfter, ...paramInputs.map(x => x.input)].forEach(el => {
        el.addEventListener('input', update);
        el.addEventListener('change', update);
    });

    copyBtn.addEventListener('click', () => {
        copyText(requestJson(build()), 'Request copied — send it to whoever should approve it');
    });
    saveBtn.addEventListener('click', () => saveTokenFile(build()));
    signBtn.addEventListener('click', async () => {
        const req = build();
        signBtn.disabled = true;
        error.textContent = 'Redirecting to your identity provider…';
        try {
            await beginSigning({ action: 'approve', command: req.command, approvals: [] });
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
                    h('div', { class: 'modal-title' }, 'Configure the request')),
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
                    h('div', { class: 'label' }, 'What it needs'),
                    factRows(requirementFacts(cmd, null)),
                    h('p', { class: 'hint' },
                        'Approve adds your approval. If more are needed, save the result and send it on; ' +
                        'whoever runs it is logged in and checked by policy too.')),
                h('div', { class: 'code-head' },
                    h('span', { class: 'label' }, 'Signed payload'),
                    h('span', { class: 'hint' }, 'exactly what every approval covers')),
                preview),
            h('div', { class: 'modal-foot' },
                error,
                h('span', { class: 'spacer' }),
                h('button', { class: 'btn btn-ghost', type: 'button', onclick: close }, 'Cancel'),
                copyBtn,
                saveBtn,
                signBtn)));

    document.body.append(scrim);
    update();
    targets.focus();
}

// ---------------------------------------------------------------------------
// Page: Sign a request (review a request and add an approval)
// ---------------------------------------------------------------------------

async function initReviewPage() {
    const input = $('review-token');
    const detail = $('review-detail');
    const result = await takeSignResult();
    if (result) await renderSignedResult($('review-result'), result);

    const render = async (req) => {
        clear(detail);
        detail.hidden = false;
        await renderRequestReview(detail, req, (next) => {
            input.value = requestJson(next);
            render(next);
        });
    };
    const show = async () => {
        let req;
        try {
            req = parseRequest(decodeToken(input.value));
        } catch (e) {
            clear(detail);
            detail.hidden = false;
            detail.append(notice('error', e.message));
            return;
        }
        await render(req);
    };
    $('review-btn').addEventListener('click', show);
    acceptTokens(input, $('review-file'), $('review-file-input'), $('review-input'), show);
    $('agent-url').addEventListener('change', () => { if (!detail.hidden) show(); });

    // Another page may hand a request over; nothing is signed without a click.
    const prefill = takeHandOff();
    if (prefill) {
        input.value = prefill;
        show();
    }
}

async function renderRequestReview(target, req, rerender) {
    const { problems, warnings, info } = await requestContext(req.command);
    const st = requestStatus(req, info);
    const panel = h('section', { class: 'panel accent' },
        panelTitle(req.command.command, info && info.description));
    problems.forEach(p => panel.append(notice('error', p)));
    warnings.forEach(w => panel.append(notice('warn', w)));
    const stale = staleApprovalsNotice(req, st, rerender);
    if (stale) panel.append(stale);
    if (st.complete) {
        panel.append(notice('ok', 'This request already has the approvals it needs. Run it from Execute.'));
    }

    panel.append(factRows([...commandFacts(req.command), ...approvalFacts(st), ...requirementFacts(info, st)]));
    if (req.approvals.length) {
        panel.append(h('p', { class: 'hint' },
            'Approvers are read from the tokens in the file; the agent verifies them before running anything.'));
    }
    panel.append(
        h('div', { class: 'code-head' },
            h('span', { class: 'label' }, 'Signed payload'),
            h('span', { class: 'hint' }, 'exactly what your approval covers')),
        h('pre', { class: 'code-block' }, signedPayloadText(req.command)));

    const status = h('span', { class: 'hint-line' }, 'Approving asks you to log in again, and uses a one-time key.');
    const approveBtn = h('button', { class: st.complete ? 'btn' : 'btn btn-primary', disabled: problems.length > 0 },
        icon('sign'), 'Approve');
    approveBtn.addEventListener('click', async () => {
        approveBtn.disabled = true;
        status.textContent = 'Redirecting to your identity provider…';
        try {
            await beginSigning({ action: 'approve', command: req.command, approvals: req.approvals });
        } catch (e) {
            status.textContent = 'Could not start signing: ' + e.message;
            approveBtn.disabled = false;
        }
    });
    const execBtn = req.approvals.length
        ? h('button', { class: st.complete ? 'btn btn-primary' : 'btn', onclick: () => handOff('/ui/execute', req) },
            icon('play'), 'Open in Execute')
        : null;
    panel.append(h('div', { class: 'actions' }, status, h('span', { class: 'spacer' }), approveBtn, execBtn));
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
            ? notice('ok', (result.body && result.body.message) || 'Request revoked.')
            : notice('error', `Revocation refused (${result.status}): ` +
                ((result.body && result.body.error) || JSON.stringify(result.body))));
    } else if (result && result.outcome === 'error') {
        resultBox.append(notice('error', 'Revocation failed: ' + result.message));
    }

    const render = async (req) => {
        clear(detail);
        detail.hidden = false;
        if (req.approvals.length === 0) {
            detail.append(h('section', { class: 'panel' },
                notice('warn', 'This request has no approvals yet, so there is nothing to run. Approve it first.'),
                h('div', { class: 'actions' },
                    h('span', { class: 'spacer' }),
                    h('button', { class: 'btn btn-primary', onclick: () => handOff('/ui/review', req) },
                        icon('fingerprint'), 'Open in Sign a request'))));
            return;
        }
        await renderExecuteDetail(detail, req, (next) => {
            input.value = requestJson(next);
            render(next);
        });
    };
    const show = async () => {
        let req;
        try {
            req = parseRequest(decodeToken(input.value));
        } catch (e) {
            clear(detail);
            detail.hidden = false;
            detail.append(notice('error', e.message));
            return;
        }
        await render(req);
    };
    $('exec-btn').addEventListener('click', show);
    acceptTokens(input, $('exec-file'), $('exec-file-input'), $('exec-input'), show);
    $('agent-url').addEventListener('change', () => { if (!detail.hidden) show(); });

    const handed = takeHandOff();
    if (handed) {
        input.value = handed;
        show();
    }
}

async function renderExecuteDetail(target, req, rerender) {
    const { problems, warnings, info } = await requestContext(req.command);
    const st = requestStatus(req, info);
    const panel = h('section', { class: 'panel accent' },
        panelTitle(req.command.command, info && info.description));
    problems.forEach(p => panel.append(notice('error', p)));
    warnings.forEach(w => panel.append(notice('warn', w)));
    const stale = staleApprovalsNotice(req, st, rerender);
    if (stale) panel.append(stale);
    if (st.complete === false) {
        panel.append(notice('warn', `Not enough approvals yet: still needs ${missingText(st)}. ` +
            'The agent will refuse it until they are added under "Sign a request".'));
    }
    panel.append(factRows([...commandFacts(req.command), ...approvalFacts(st), ...requirementFacts(info, st)]));

    const status = h('span', { class: 'hint-line' },
        'Runs on the agent selected at the top, as you: policy checks who may run it.');
    const execBtn = h('button', { class: 'btn btn-primary' }, icon('play'), 'Execute');
    execBtn.addEventListener('click', async () => {
        execBtn.disabled = true;
        status.textContent = 'Submitting to ' + agentDisplay() + '…';
        try {
            await executeBundle(req);
        } catch (e) {
            status.textContent = 'The agent refused: ' + e.message;
            execBtn.disabled = false;
        }
    });
    const revokeBtn = h('button', { class: 'btn btn-danger', title: 'Approvers may always revoke; anyone else needs policy\'s permission' },
        icon('revoke'), 'Revoke request');
    revokeBtn.addEventListener('click', async () => {
        const agent = agentDisplay();
        if (!confirm(`Revoke this '${req.command.command}' request on ${agent}? ` +
            'It will not run there (or on any agent sharing a revocation service), whoever approves it. ' +
            'You will be asked to log in again. This cannot be undone.')) return;
        revokeBtn.disabled = true;
        status.textContent = 'Redirecting to your identity provider…';
        try {
            await beginSigning({ action: 'revoke', request: { command: req.command, approvals: req.approvals }, agent_url: agentUrl() });
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
    if (params.get('agent_url')) setAgent(params.get('agent_url'));

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
    // Rows received while follow is off: kept, shown when it's turned on.
    const held = [];
    let partial = '';
    let inHeader = false;
    let finished = false;

    const setState = (state, label) => {
        pill.dataset.state = state;
        pill.lastChild.textContent = label || state;
    };

    const factMap = new Map();
    const approvedBy = [];
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
    setFact('Agent', agentIsLocal() ? `This machine · ${document.body.dataset.signerHost}` : agentDisplay());
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
        const onScreen = lines.length - held.length;
        const visible = lines.filter(l => l.el.isConnected && !l.el.classList.contains('hidden')).length;
        shown.textContent = `${visible.toLocaleString()} of ${onScreen.toLocaleString()} lines` +
            (held.length ? ` · paused, ${held.length.toLocaleString()} new ${held.length === 1 ? 'line' : 'lines'} held` : '');
    };

    // The agent writes a header block before the command's output and a
    // trailer when it ends; both are real facts about the run.
    const classify = (text, row) => {
        if (!isRun) return;
        if (text === '--- EXECUTION LOG ---') { inHeader = true; row.classList.add('meta'); return; }
        if (inHeader) {
            row.classList.add('meta');
            if (/^-+$/.test(text)) { inHeader = false; return; }
            const m = text.match(/^(ID|Request|Approver|Executor|Time|Command|Executable): (.*)$/);
            if (m && m[1] === 'Approver') {
                // "name (RFC 3339 signing time)", one line per approver.
                const a = m[2].match(/^(.*) \(([^()]*)\)$/);
                approvedBy.push(a ? `${a[1]} (${fmtTime(a[2])})` : m[2]);
                setFact('Approved by', approvedBy.join(', '));
            } else if (m) {
                const label = { ID: null, Request: 'Request', Executor: 'Run by', Time: 'Started', Command: 'Command', Executable: 'Executable' }[m[1]];
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
        if (follow) out.append(row);
        else held.push(row);
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
    // Like tail -f: off pauses the view. Lines keep arriving and are held
    // (nothing is lost), then shown when follow is turned back on.
    followBtn.addEventListener('click', () => {
        follow = !follow;
        followBtn.classList.toggle('on', follow);
        if (follow) {
            out.append(...held.splice(0));
            out.scrollTop = out.scrollHeight;
        }
        updateCount();
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
