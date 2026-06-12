// Shared logic for the Remonce signer UI.
//
// Wire format notes:
//  - Draft token  = base64(JSON { command: {...}, operator_requires: {...}|null })
//  - Signed token = base64(JSON ExecutionBundle { approver: {...}, operator: null })
//  - Cosigned     = ExecutionBundle with operator filled in
// All agent traffic goes through the loopback web tier proxy
// (/api/agent/*, /ws/*) — the browser never talks to the agent directly.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}

function getAgentUrl() {
    const stored = localStorage.getItem('remonce.agentUrl');
    if (stored && stored.trim()) return stored.trim();
    const meta = document.querySelector('meta[name="remonce-agent-url"]');
    return meta ? meta.content : '';
}

function setAgentUrl(url) {
    localStorage.setItem('remonce.agentUrl', url.trim());
}

// Render the agent URL input into any page that has #agent-url-area.
function initAgentUrlArea() {
    const area = document.getElementById('agent-url-area');
    if (!area) return;
    area.innerHTML = `
        <div class="input-group input-group-sm mb-3" style="max-width: 480px;">
            <span class="input-group-text bg-dark text-secondary border-secondary">Agent</span>
            <input type="text" id="agent-url-input"
                class="form-control bg-dark text-light border-secondary"
                placeholder="https://agent-host:10022" value="${escapeHtml(getAgentUrl())}">
        </div>`;
    document.getElementById('agent-url-input').addEventListener('change', (e) => {
        setAgentUrl(e.target.value);
    });
}

function currentAgentUrl() {
    const input = document.getElementById('agent-url-input');
    if (input && input.value.trim()) {
        setAgentUrl(input.value);
        return input.value.trim();
    }
    return getAgentUrl();
}

// Decode a token that may be base64-wrapped JSON or raw JSON.
function decodeFlexible(raw) {
    const trimmed = raw.trim();
    if (trimmed.startsWith('{')) return JSON.parse(trimmed);
    return JSON.parse(atob(trimmed));
}

// Best-effort decode of a JWT payload for *display only*. The agent is the
// verification authority; this is informational.
function decodeJwtPayload(jwt) {
    try {
        const part = jwt.split('.')[1];
        return JSON.parse(atob(part.replace(/-/g, '+').replace(/_/g, '/')));
    } catch (e) {
        return null;
    }
}

function downloadJson(filename, obj) {
    const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
}

function copyButtonFeedback(btn, label) {
    const original = label || btn.innerText;
    btn.innerText = 'Copied!';
    setTimeout(() => btn.innerText = original, 2000);
}

function describeOperatorRequires(req) {
    if (!req || !req.any_of || req.any_of.length === 0) {
        return '<span class="text-muted">Any authorized operator</span>';
    }
    const parts = req.any_of.map(p => {
        const v = typeof p.value === 'string' ? p.value : JSON.stringify(p.value);
        const verb = p.op === 'contains' ? 'contains' : '=';
        return `<code>${escapeHtml(p.claim)} ${verb} ${escapeHtml(v)}</code>`;
    });
    return 'Operator must match at least one of: ' + parts.join(' , ');
}

function describeConstraints(command) {
    let html = '';
    if (command.target_machines && command.target_machines.length > 0) {
        html += `<div><strong>Targets:</strong> ${escapeHtml(command.target_machines.join(', '))}</div>`;
    }
    if (command.not_before) {
        html += `<div><strong>Not Before:</strong> ${new Date(command.not_before).toLocaleString()}</div>`;
    }
    if (command.not_after) {
        html += `<div><strong>Not After:</strong> ${new Date(command.not_after).toLocaleString()}</div>`;
    }
    return html || '<span class="text-muted">None</span>';
}

// Submit an ExecutionBundle to the agent via the web-tier proxy. Returns the
// execution id on success; throws on failure.
async function submitBundle(bundle) {
    const res = await fetch('/api/agent/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent_url: currentAgentUrl(), bundle: bundle })
    });
    const text = await res.text();
    if (!res.ok) {
        let msg = `Agent returned ${res.status}`;
        try {
            const data = JSON.parse(text);
            if (data && data.error) msg = data.error;
            else if (text.trim()) msg += `: ${text}`;
        } catch (_) {
            if (text.trim()) msg += `: ${text}`;
        }
        throw new Error(msg);
    }
    const data = JSON.parse(text);
    return data.message || (bundle.approver.command && bundle.approver.command.id);
}

function gotoMonitor(executionId) {
    const params = new URLSearchParams();
    params.set('id', executionId);
    const agent = currentAgentUrl();
    if (agent) params.set('agent_url', agent);
    window.location.href = `/ui/monitor?${params.toString()}`;
}

// ---------------------------------------------------------------------------
// Page wiring
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
    initAgentUrlArea();

    // Page: Generate - Token Copy
    const copyBtn = document.getElementById('copy-token-btn');
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const tokenText = document.getElementById('generated-token');
            navigator.clipboard.writeText(tokenText.value);
            copyButtonFeedback(copyBtn, 'Copy to Clipboard');
        });
    }

    // Page: Inspect
    const inspectBtn = document.getElementById('inspect-btn');
    if (inspectBtn) inspectBtn.addEventListener('click', handleInspectToken);

    const signTokenBtn = document.getElementById('sign-token-btn');
    if (signTokenBtn) signTokenBtn.addEventListener('click', handleSignToken);

    const copySignedBtn = document.getElementById('copy-signed-btn');
    if (copySignedBtn) {
        copySignedBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(document.getElementById('signed-token-output').value);
            copyButtonFeedback(copySignedBtn, 'Copy Token');
        });
    }

    const downloadSignedBtn = document.getElementById('download-signed-btn');
    if (downloadSignedBtn) {
        downloadSignedBtn.addEventListener('click', () => {
            if (window.signedBundle) {
                const name = (window.signedBundle.approver.command.command || 'command');
                downloadJson(`remonce-${name}-approval.json`, window.signedBundle);
            }
        });
    }

    const executeNowBtn = document.getElementById('execute-now-btn');
    if (executeNowBtn) {
        executeNowBtn.addEventListener('click', async () => {
            if (!window.signedBundle) return;
            executeNowBtn.disabled = true;
            executeNowBtn.innerText = 'Submitting...';
            try {
                const id = await submitBundle(window.signedBundle);
                gotoMonitor(id);
            } catch (e) {
                alert('Execution Error: ' + e.message);
                executeNowBtn.disabled = false;
                executeNowBtn.innerText = 'Execute Now';
            }
        });
    }

    // Page: Execute
    const executeTokenBtn = document.getElementById('execute-token-btn');
    if (executeTokenBtn) {
        executeTokenBtn.addEventListener('click', handleExecuteToken);
        const urlParams = new URLSearchParams(window.location.search);
        const signedToken = urlParams.get('signed_token');
        if (signedToken) {
            const input = document.getElementById('signed-token-input');
            if (input) {
                input.value = signedToken;
                executeTokenBtn.click();
            }
        }
    }

    // Page: Cosign
    const cosignInspectBtn = document.getElementById('cosign-inspect-btn');
    if (cosignInspectBtn) cosignInspectBtn.addEventListener('click', handleCosignInspect);

    const cosignBtn = document.getElementById('cosign-btn');
    if (cosignBtn) cosignBtn.addEventListener('click', handleCosign);
});

// ---------------------------------------------------------------------------
// Generate page
// ---------------------------------------------------------------------------

async function loadCommandsForGenerate() {
    const list = document.getElementById('commands-list-generate');
    if (!list) return;

    list.innerHTML = 'Loading...';
    try {
        const res = await fetch('/api/commands');
        if (res.status === 403) {
            list.innerHTML = '<div style="color:red">Access Denied: You do not have permission to view commands.</div>';
            return;
        }
        if (!res.ok) throw new Error(await res.text());

        const commands = await res.json();

        let html = '';

        // Custom Command card first.
        html += `<div class="col-md-6 col-lg-4">
            <div class="card h-100 shadow-sm border-warning bg-dark text-light">
                <div class="card-body d-flex flex-column">
                    <h5 class="card-title text-warning">Custom Command</h5>
                     <p class="card-text text-muted small">Generate a token for a command not in the registry (it must exist in the agent's config).</p>
                    <div class="mt-auto pt-3">
                         <input type="text" id="custom-command-name"
                            class="form-control form-control-sm bg-dark text-light border-secondary mb-2"
                            placeholder="e.g. backup-db">
                        <button class="btn btn-sm btn-outline-warning w-100" onclick="generateCustomToken()">Generate Custom</button>
                    </div>
                </div>
            </div>
        </div>`;

        commands.forEach(cmd => {
            const desc = cmd.description ? `<p class="card-text text-muted small">${escapeHtml(cmd.description)}</p>` : '';
            const approverValidity = cmd.approver_max_validity || '3d (default)';
            const validity = `<span class="badge bg-secondary mb-2" title="Approver Max Validity">${escapeHtml(String(approverValidity))}</span>`;

            html += `<div class="col-md-6 col-lg-4">
                <div class="card h-100 shadow-sm border-secondary">
                    <div class="card-body d-flex flex-column">
                        <div class="d-flex justify-content-between align-items-start">
                            <h5 class="card-title text-primary">${escapeHtml(cmd.name)}</h5>
                            ${validity}
                        </div>
                        ${desc}
                        <div class="mt-auto pt-3 d-flex justify-content-between align-items-center">
                             <button class="btn btn-sm btn-outline-success" onclick="generateToken('${escapeHtml(cmd.name)}')">Generate Command</button>
                        </div>
                    </div>
                </div>
            </div>`;
        });
        list.innerHTML = html;
    } catch (e) {
        list.innerHTML = `<div style="color:red">Error loading commands: ${escapeHtml(e.message)}</div>`;
    }
}

function getConstraints() {
    const targets = document.getElementById('target-machines').value.trim();
    const notBefore = document.getElementById('not-before').value;
    const notAfter = document.getElementById('not-after').value;

    const constraints = {};
    if (targets) {
        constraints.target_machines = targets.split(',').map(s => s.trim()).filter(s => s);
    }
    if (notBefore) {
        constraints.not_before = new Date(notBefore).toISOString();
    }
    if (notAfter) {
        const d = new Date(notAfter);
        d.setSeconds(59);
        d.setMilliseconds(999);
        constraints.not_after = d.toISOString();
    }
    return constraints;
}

// --- operator_requires builder ---

function addOpReqRow(claim, op, value) {
    const container = document.getElementById('opreq-rows');
    if (!container) return;
    const row = document.createElement('div');
    row.className = 'input-group input-group-sm mb-2 opreq-row';
    row.innerHTML = `
        <input type="text" class="form-control bg-dark text-light border-secondary opreq-claim"
            placeholder="claim (e.g. groups)" value="${escapeHtml(claim || '')}">
        <select class="form-select bg-dark text-light border-secondary opreq-op" style="max-width: 130px;">
            <option value="contains">contains</option>
            <option value="equals">equals</option>
        </select>
        <input type="text" class="form-control bg-dark text-light border-secondary opreq-value"
            placeholder="value (e.g. noc-l2)" value="${escapeHtml(value || '')}">
        <button class="btn btn-outline-danger" type="button" onclick="this.closest('.opreq-row').remove()">&times;</button>`;
    if (op) row.querySelector('.opreq-op').value = op;
    container.appendChild(row);
}

function getOperatorRequires() {
    const rows = document.querySelectorAll('.opreq-row');
    const any_of = [];
    rows.forEach(row => {
        const claim = row.querySelector('.opreq-claim').value.trim();
        const op = row.querySelector('.opreq-op').value;
        const rawValue = row.querySelector('.opreq-value').value.trim();
        if (!claim || !rawValue) return;
        let value;
        try { value = JSON.parse(rawValue); } catch (_) { value = rawValue; }
        any_of.push({ op: op, claim: claim, value: value });
    });
    return any_of.length > 0 ? { any_of: any_of } : null;
}

function generateToken(commandName) {
    const constraints = getConstraints();
    const draft = {
        command: {
            command: commandName,
            id: crypto.randomUUID(),
            ...constraints
        },
        operator_requires: getOperatorRequires()
    };
    renderTokenModal(draft);
}

function generateCustomToken() {
    const commandName = document.getElementById('custom-command-name').value.trim();
    if (!commandName) {
        alert('Please enter a command name');
        return;
    }
    if (/\s/.test(commandName)) {
        alert('Command names cannot contain spaces. Correct format: "backup-db", not "backup db"');
        return;
    }
    generateToken(commandName);
}

function renderTokenModal(draft) {
    const token = btoa(JSON.stringify(draft));
    document.getElementById('generated-token').value = token;

    const inspectBtn = document.getElementById('go-to-inspect-btn');
    if (inspectBtn) {
        inspectBtn.href = `/ui/inspect?token=${encodeURIComponent(token)}`;
    }

    const modal = new bootstrap.Modal(document.getElementById('tokenModal'));
    modal.show();
}

// ---------------------------------------------------------------------------
// Inspect & Sign page
// ---------------------------------------------------------------------------

function initInspectPage() {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    if (token) {
        document.getElementById('draft-token-input').value = token;
        handleInspectToken();
    }
}

// Normalize a draft token into { command, operator_requires }. Accepts the
// wrapper format and the legacy flat command object.
function parseDraft(raw) {
    const parsed = decodeFlexible(raw);
    if (parsed.command && typeof parsed.command === 'object') {
        return { command: parsed.command, operator_requires: parsed.operator_requires || null };
    }
    if (typeof parsed.command === 'string') {
        return { command: parsed, operator_requires: null };
    }
    throw new Error('Invalid token structure');
}

function handleInspectToken() {
    const input = document.getElementById('draft-token-input');
    const resultArea = document.getElementById('inspection-result');

    try {
        const draft = parseDraft(input.value);
        if (!draft.command.command || !draft.command.id) {
            throw new Error('Invalid token structure');
        }

        document.getElementById('detail-command').innerText = draft.command.command;
        document.getElementById('detail-id').innerText = draft.command.id;
        document.getElementById('detail-constraints').innerHTML = describeConstraints(draft.command);
        document.getElementById('detail-opreq').innerHTML = describeOperatorRequires(draft.operator_requires);

        window.currentDraft = draft;
        resultArea.style.display = 'block';
    } catch (e) {
        alert('Invalid Token: ' + e.message);
        resultArea.style.display = 'none';
    }
}

async function handleSignToken() {
    const signBtn = document.getElementById('sign-token-btn');
    if (!window.currentDraft) return;

    signBtn.disabled = true;
    signBtn.innerText = 'Signing...';

    try {
        const response = await fetch('/api/sign', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                command: window.currentDraft.command,
                operator_requires: window.currentDraft.operator_requires
            })
        });

        if (!response.ok) {
            throw new Error('Signing failed: ' + await response.text());
        }

        const bundle = await response.json();
        window.signedBundle = bundle;

        document.getElementById('signed-token-output').value = btoa(JSON.stringify(bundle));
        document.getElementById('signed-result-area').style.display = 'block';

        signBtn.innerText = 'Signed Successfully';
    } catch (err) {
        alert('Error: ' + err.message);
        signBtn.disabled = false;
        signBtn.innerText = 'Sign Command';
    }
}

// ---------------------------------------------------------------------------
// Execute page
// ---------------------------------------------------------------------------

function parseBundle(raw) {
    const parsed = decodeFlexible(raw);
    if (parsed.approver && parsed.approver.signature) return parsed;       // ExecutionBundle
    if (parsed.signature && parsed.command) {                               // bare ApproverBundle
        return { approver: parsed, operator: null };
    }
    throw new Error('Not a recognizable execution bundle');
}

async function handleExecuteToken() {
    const input = document.getElementById('signed-token-input');
    const btn = document.getElementById('execute-token-btn');

    if (!input.value.trim()) {
        alert('Please paste a token');
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Submitting...';

    try {
        const bundle = parseBundle(input.value);
        const id = await submitBundle(bundle);
        if (!id) {
            alert('Execution started, but no ID returned for monitoring.');
            return;
        }
        gotoMonitor(id);
    } catch (e) {
        alert('Execution Error: ' + e.message);
    } finally {
        btn.disabled = false;
        btn.textContent = 'Execute';
    }
}

// ---------------------------------------------------------------------------
// Cosign page
// ---------------------------------------------------------------------------

function handleCosignInspect() {
    const input = document.getElementById('cosign-token-input');
    const resultArea = document.getElementById('cosign-inspection-result');

    try {
        const bundle = parseBundle(input.value);
        const approver = bundle.approver;
        const command = approver.command;

        document.getElementById('cosign-detail-command').innerText = command.command || '(unknown)';
        document.getElementById('cosign-detail-id').innerText = command.id || '(none)';
        document.getElementById('cosign-detail-constraints').innerHTML = describeConstraints(command);
        document.getElementById('cosign-detail-opreq').innerHTML = describeOperatorRequires(approver.operator_requires);

        const claims = decodeJwtPayload(approver.id_token);
        const approverLabel = claims
            ? `${escapeHtml(claims.username || claims.sub || 'unknown')}${claims.groups ? ' — groups: ' + escapeHtml(JSON.stringify(claims.groups)) : ''}`
            : '<span class="text-warning">could not decode</span>';
        document.getElementById('cosign-detail-approver').innerHTML =
            `${approverLabel} <span class="text-muted small">(as claimed — the agent verifies cryptographically)</span>`;

        window.cosignApprover = approver;
        resultArea.style.display = 'block';
    } catch (e) {
        alert('Invalid bundle: ' + e.message);
        resultArea.style.display = 'none';
    }
}

async function handleCosign() {
    const btn = document.getElementById('cosign-btn');
    if (!window.cosignApprover) return;

    btn.disabled = true;
    btn.innerText = 'Co-signing...';

    try {
        const response = await fetch('/api/cosign', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ approver: window.cosignApprover })
        });
        if (!response.ok) {
            throw new Error('Cosign failed: ' + await response.text());
        }
        const bundle = await response.json();
        window.signedBundle = bundle;

        document.getElementById('signed-token-output').value = btoa(JSON.stringify(bundle));
        document.getElementById('signed-result-area').style.display = 'block';
        btn.innerText = 'Co-signed';
    } catch (e) {
        alert('Error: ' + e.message);
        btn.disabled = false;
        btn.innerText = 'Co-sign as Me';
    }
}

// ---------------------------------------------------------------------------
// Monitor page (execution logs + file streaming, via the web-tier WS proxy)
// ---------------------------------------------------------------------------

function initMonitorPage() {
    const urlParams = new URLSearchParams(window.location.search);
    const id = urlParams.get('id');
    const fileName = urlParams.get('file_name');
    const filePath = urlParams.get('file_path');
    const agentUrl = urlParams.get('agent_url');
    if (agentUrl) setAgentUrl(agentUrl);

    const startBtn = document.getElementById('start-monitor-btn');
    if (startBtn) {
        startBtn.addEventListener('click', () => {
            const val = document.getElementById('execution-id-input').value.trim();
            if (val) {
                const params = new URLSearchParams();
                params.set('id', val);
                const agent = currentAgentUrl();
                if (agent) params.set('agent_url', agent);
                window.location.href = `/ui/monitor?${params.toString()}`;
            }
        });
    }

    if (id) {
        const inputArea = document.getElementById('monitor-input-area');
        if (inputArea) inputArea.style.display = 'none';
        startStreaming({ type: 'execution', id: id });
    } else if (fileName || filePath) {
        const inputArea = document.getElementById('monitor-input-area');
        if (inputArea) inputArea.style.display = 'none';

        const tailControls = document.getElementById('tail-controls');
        if (tailControls) tailControls.style.display = 'flex';

        startStreaming({
            type: 'file',
            name: fileName,
            path: filePath,
            tailLines: urlParams.get('tail_lines')
        });
    }
}

function reloadStream(lines) {
    const urlParams = new URLSearchParams(window.location.search);
    urlParams.set('tail_lines', lines);
    window.location.search = urlParams.toString();
}

function wsBase() {
    return window.location.origin.replace(/^http/, 'ws');
}

function startStreaming(target) {
    const agentOutput = document.getElementById('agent-output');
    const statusArea = document.getElementById('status-area');
    const agentArea = document.getElementById('agent-result-area');
    const spinner = document.getElementById('loading-spinner');

    agentArea.style.display = 'block';
    if (spinner) spinner.style.display = 'inline-block';
    agentOutput.innerHTML = '';

    const params = new URLSearchParams();
    const agent = getAgentUrl();
    if (agent) params.set('agent_url', agent);

    let wsUrl = '';
    if (target.type === 'execution') {
        params.set('id', target.id);
        wsUrl = `${wsBase()}/ws/exec?${params.toString()}`;
        statusArea.innerText = `Streaming logs for Execution ID: ${target.id}`;
    } else if (target.type === 'file') {
        if (target.name) params.set('name', target.name);
        if (target.path) params.set('path', target.path);
        if (target.tailLines) params.set('tail_lines', target.tailLines);
        wsUrl = `${wsBase()}/ws/file?${params.toString()}`;
        statusArea.innerText = `Streaming file: ${target.name || target.path}`;
    }

    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        const info = document.createElement('div');
        info.textContent = `[Connected to stream]`;
        info.style.color = "#339af0";
        agentOutput.style.whiteSpace = "pre-wrap";
        agentOutput.style.fontFamily = "var(--bs-font-monospace)";
        agentOutput.appendChild(info);
        statusArea.innerText = "Connected";
        if (spinner) spinner.style.display = 'none';
    };

    ws.onmessage = (event) => {
        const logSpan = document.createElement('span');
        logSpan.textContent = event.data;
        agentOutput.appendChild(logSpan);
        agentOutput.scrollTop = agentOutput.scrollHeight;
    };

    ws.onclose = () => {
        const info = document.createElement('div');
        info.textContent = `[Stream finished]`;
        info.style.color = "gray";
        agentOutput.appendChild(info);
        statusArea.innerText = "Disconnected";
        if (spinner) spinner.style.display = 'none';
    };

    ws.onerror = () => {
        const info = document.createElement('div');
        info.textContent = `[Connection Error]`;
        info.style.color = "red";
        agentOutput.appendChild(info);
        statusArea.innerText = "Error";
        if (spinner) spinner.style.display = 'none';
    };
}

// ---------------------------------------------------------------------------
// Files page
// ---------------------------------------------------------------------------

async function refreshFiles() {
    const list = document.getElementById('files-list-container');
    if (!list) return;

    list.innerHTML = 'Loading files...';
    try {
        const params = new URLSearchParams();
        const agent = currentAgentUrl();
        if (agent) params.set('agent_url', agent);
        const res = await fetch(`/api/agent/files?${params.toString()}`);
        if (!res.ok) throw new Error(`Agent returned ${res.status}: ${await res.text()}`);
        const files = await res.json();

        if (files.length === 0) {
            list.innerHTML = '<div class="col-12 text-muted">No files defined in configuration.</div>';
            return;
        }

        const groups = {};
        files.forEach(f => {
            const key = f.name || f.path;
            if (!groups[key]) groups[key] = { name: f.name, desc: f.description, paths: [] };
            groups[key].paths.push(f.path);
        });

        let html = '';
        Object.keys(groups).sort().forEach(key => {
            const g = groups[key];
            const isMulti = g.paths.length > 1;
            const displayName = g.name || g.paths[0];
            const desc = g.desc ? `<p class="mb-2 text-muted small">${escapeHtml(g.desc)}</p>` : '';

            let content = '';
            if (isMulti) {
                const options = g.paths.map(p =>
                    `<option value="${escapeHtml(p)}" title="${escapeHtml(p)}">${escapeHtml(p.split(/[\\/]/).pop())}</option>`
                ).join('');

                content = `
                    <div class="mb-2">
                         <label class="form-label text-secondary small">Select File (${g.paths.length}):</label>
                         <select id="select-${escapeHtml(key)}" class="form-select form-select-sm bg-dark text-light border-secondary">
                             ${options}
                         </select>
                    </div>
                    <button class="btn btn-sm btn-outline-info w-100"
                        onclick="viewSelectedFile('select-${escapeHtml(key)}')">
                        Read Selected
                    </button>`;
            } else {
                const path = g.paths[0];
                const subText = g.name ? `<small class="text-secondary d-block text-truncate mb-2" title="${escapeHtml(path)}">${escapeHtml(path)}</small>` : '';
                content = `
                    ${subText}
                    <button class="btn btn-sm btn-outline-info w-100"
                        onclick="viewFile(null, '${escapeHtml(path.replace(/\\/g, '\\\\'))}')">
                        Read File
                    </button>`;
            }

            html += `<div class="col-md-6 col-lg-4">
                <div class="card bg-dark border-secondary h-100 shadow-sm">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-start mb-2">
                             <h6 class="card-title text-info text-truncate mb-0" title="${escapeHtml(displayName)}">${escapeHtml(displayName)}</h6>
                        </div>
                        ${desc}
                        <div class="mt-3">
                            ${content}
                        </div>
                    </div>
                </div>
            </div>`;
        });
        list.innerHTML = html;

    } catch (e) {
        list.innerHTML = `<div class="col-12 text-danger">Failed to load files: ${escapeHtml(e.message)}. Is the agent reachable?</div>`;
    }
}

function viewSelectedFile(selectId) {
    const select = document.getElementById(selectId);
    if (select && select.value) {
        viewFile(null, select.value);
    }
}

function viewFile(name, path) {
    const params = new URLSearchParams();
    if (name) params.append('file_name', name);
    else if (path) params.append('file_path', path);
    params.append('tail_lines', '1000');
    const agent = currentAgentUrl();
    if (agent) params.append('agent_url', agent);
    window.location.href = `/ui/monitor?${params.toString()}`;
}
