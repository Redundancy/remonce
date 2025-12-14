// Shared logic for Remonse UI

document.addEventListener('DOMContentLoaded', () => {
    // Page: Commands
    if (document.getElementById('commands-list')) {
        // loadCommands is called by inline script, or we can call it here?
        // Inline script in commands.html calls it.
    }

    // Page: Sign
    const signBtn = document.getElementById('sign-btn');
    if (signBtn) {
        signBtn.addEventListener('click', handleSignAndExecute);
    }

    // Page: Generate - Token Copy
    const copyBtn = document.getElementById('copy-token-btn');
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const tokenText = document.getElementById('generated-token');
            tokenText.select();
            navigator.clipboard.writeText(tokenText.value);
            copyBtn.innerText = 'Copied!';
            setTimeout(() => copyBtn.innerText = 'Copy to Clipboard', 2000);
        });
    }

    // Page: Inspect
    const inspectBtn = document.getElementById('inspect-btn');
    if (inspectBtn) {
        inspectBtn.addEventListener('click', handleInspectToken);
    }

    const signTokenBtn = document.getElementById('sign-token-btn');
    if (signTokenBtn) {
        signTokenBtn.addEventListener('click', handleSignToken);
    }

    const copySignedBtn = document.getElementById('copy-signed-btn');
    if (copySignedBtn) {
        copySignedBtn.addEventListener('click', () => {
            const tokenText = document.getElementById('signed-token-output');
            tokenText.select();
            navigator.clipboard.writeText(tokenText.value);
            copySignedBtn.innerText = 'Copied!';
            setTimeout(() => copySignedBtn.innerText = 'Copy Signed Token', 2000);
        });
    }

    const executeNowBtn = document.getElementById('execute-now-btn');
    if (executeNowBtn) {
        executeNowBtn.addEventListener('click', () => {
            const token = document.getElementById('signed-token-output').value;
            if (token) {
                window.location.href = `/ui/execute?signed_token=${encodeURIComponent(token)}`;
            }
        });
    }

    // Page: Execute
    const executeTokenBtn = document.getElementById('execute-token-btn');
    if (executeTokenBtn) {
        executeTokenBtn.addEventListener('click', handleExecuteToken);

        // Auto-fill and execute if token present in URL
        const urlParams = new URLSearchParams(window.location.search);
        const signedToken = urlParams.get('signed_token');
        if (signedToken) {
            const input = document.getElementById('signed-token-input');
            if (input) {
                input.value = signedToken;
                // Auto-click execute
                executeTokenBtn.click();
            }
        }
    }
});

function initMonitorPage() {
    const urlParams = new URLSearchParams(window.location.search);
    const id = urlParams.get('id');

    // Handle manual entry
    const startBtn = document.getElementById('start-monitor-btn');
    if (startBtn) {
        startBtn.addEventListener('click', () => {
            const val = document.getElementById('execution-id-input').value.trim();
            if (val) {
                // Update URL to make it shareable/refreshable
                window.location.href = `/ui/monitor?id=${val}`;
            }
        });
    }

    if (id) {
        // Hide input, show monitor
        const inputArea = document.getElementById('monitor-input-area');
        if (inputArea) inputArea.style.display = 'none';
        startStreaming(id);
    }
}

async function loadCommands() {
    const list = document.getElementById('commands-list');
    if (!list) return;

    list.innerHTML = 'Loading...';
    try {
        const res = await fetch('/api/commands');
        if (res.status === 403) {
            list.innerHTML = '<div style="color:red">Access Denied: You do not have permission to view commands.</div>';
            return;
        }
        if (!res.ok) {
            throw new Error(await res.text());
        }
        const commands = await res.json();
        if (commands.length === 0) {
            list.innerHTML = 'No commands available.';
            return;
        }

        let html = '';
        commands.forEach(cmd => {
            const desc = cmd.description ? `<p class="card-text text-muted small">${cmd.description}</p>` : '';
            html += `<div class="col-md-6 col-lg-4">
                <div class="card h-100 shadow-sm border-secondary">
                    <div class="card-body d-flex flex-column">
                        <h5 class="card-title text-primary">${cmd.name}</h5>
                        ${desc}
                        <div class="mt-auto pt-3 d-flex justify-content-between align-items-center">
                             <a href="/ui/generate" class="btn btn-sm btn-outline-primary">Go to Generate</a>
                        </div>
                    </div>
                </div>
            </div>`;
        });
        list.innerHTML = html;
    } catch (e) {
        list.innerHTML = `<div style="color:red">Error loading commands: ${e.message}</div>`;
    }
}

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
        if (commands.length === 0) {
            list.innerHTML = 'No commands available.';
            return;
        }

        let html = '';

        // 1. Add Custom Command Card (as the first option)
        html += `<div class="col-md-6 col-lg-4">
            <div class="card h-100 shadow-sm border-warning bg-dark text-light">
                <div class="card-body d-flex flex-column">
                    <h5 class="card-title text-warning">Custom Command</h5>
                     <p class="card-text text-muted small">Generate a token for a defined command (args etc) that is not in the registry.</p>
                    <div class="mt-auto pt-3">
                         <input type="text" id="custom-command-name" 
                            class="form-control form-control-sm bg-dark text-light border-secondary mb-2" 
                            placeholder="e.g. backup-db">
                        <button class="btn btn-sm btn-outline-warning w-100" onclick="generateCustomToken()">Generate Custom</button>
                    </div>
                </div>
            </div>
        </div>`;

        // 2. Add Registered Commands
        commands.forEach(cmd => {
            const desc = cmd.description ? `<p class="card-text text-muted small">${cmd.description}</p>` : '';
            let validityStr = cmd.max_validity || '3d';
            // Normalize "3days" to "3d" if desired, or simpler: just remove "(default)" to match explicit ones if they are similar
            // If API returns "3days", we can maybe shorten it or leave it. 
            // The user complaint is one says "3days" and other says "3d (default)".
            // Let's standardise to just the value, and maybe (default) if it is missing.
            // If cmd.max_validity is "3days", show "3days". If missing, show "3days (default)"? 
            // Or force everything to short form?
            // Simplest fix: If default is "3days" (from backend logic usually), we can just set default here to "3d" and drop "(default)" text.
            // But if the backend sends "3days" for the explicit one, we might want to just show "3d" for default without text.

            validityStr = validityStr.replace('days', 'd').replace('day', 'd'); // simple normalization
            const valLabel = cmd.max_validity ? validityStr : `${validityStr} (default)`;

            const validity = `<span class="badge bg-secondary mb-2" title="Max Validity">${valLabel}</span>`;

            // Instead of link, using a button to open modal
            // We encode the command name in data attribute
            html += `<div class="col-md-6 col-lg-4">
                <div class="card h-100 shadow-sm border-secondary">
                    <div class="card-body d-flex flex-column">
                        <div class="d-flex justify-content-between align-items-start">
                            <h5 class="card-title text-primary">${cmd.name}</h5>
                            ${validity}
                        </div>
                        ${desc}
                        <div class="mt-auto pt-3 d-flex justify-content-between align-items-center">
                             <button class="btn btn-sm btn-outline-success" onclick="generateToken('${cmd.name}')">Generate Command</button>
                        </div>
                    </div>
                </div>
            </div>`;
        });
        list.innerHTML = html;
    } catch (e) {
        list.innerHTML = `<div style="color:red">Error loading commands: ${e.message}</div>`;
    }
}

// Helper to get constraints
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
        // Ensure we include the full minute by setting seconds to 59
        const d = new Date(notAfter);
        d.setSeconds(59);
        d.setMilliseconds(999);
        constraints.not_after = d.toISOString();
    }
    return constraints;
}

function generateToken(commandName) {
    const executionId = crypto.randomUUID();
    const constraints = getConstraints();

    const commandPayload = {
        command: commandName,
        id: executionId,
        ...constraints
    };

    renderTokenModal(commandPayload);
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

function renderTokenModal(payload) {
    // Create Command Token: Base64 encoded JSON
    const jsonStr = JSON.stringify(payload);
    const token = btoa(jsonStr);

    document.getElementById('generated-token').value = token;

    // Update Go to Inspect Link
    const inspectBtn = document.getElementById('go-to-inspect-btn');
    if (inspectBtn) {
        // Encode as query param
        inspectBtn.href = `/ui/inspect?token=${encodeURIComponent(token)}`;
    }

    // Show Modal
    const modalEl = document.getElementById('tokenModal');
    const modal = new bootstrap.Modal(modalEl);
    modal.show();
}

function initInspectPage() {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');

    if (token) {
        const input = document.getElementById('draft-token-input');
        input.value = token;
        // Optionally auto-inspect?
        handleInspectToken();
    }
}

function handleInspectToken() {
    const input = document.getElementById('draft-token-input');
    const resultArea = document.getElementById('inspection-result');

    try {
        const jsonStr = atob(input.value.trim());
        const payload = JSON.parse(jsonStr);

        if (!payload.command || !payload.id) {
            throw new Error('Invalid token structure');
        }

        document.getElementById('detail-command').innerText = payload.command;
        document.getElementById('detail-id').innerText = payload.id;

        // Format constraints
        let constraintsHtml = '';
        if (payload.target_machines && payload.target_machines.length > 0) {
            constraintsHtml += `<div><strong>Targets:</strong> ${payload.target_machines.join(', ')}</div>`;
        }
        if (payload.not_before) {
            constraintsHtml += `<div><strong>Not Before:</strong> ${new Date(payload.not_before).toLocaleString()}</div>`;
        }
        if (payload.not_after) {
            constraintsHtml += `<div><strong>Not After:</strong> ${new Date(payload.not_after).toLocaleString()}</div>`;
        }

        const constraintsContainer = document.getElementById('detail-constraints');
        if (constraintsHtml) {
            constraintsContainer.innerHTML = constraintsHtml;
        } else {
            constraintsContainer.innerHTML = '<span class="text-muted">None</span>';
        }

        // Store payload for signing
        window.currentPayload = payload;

        resultArea.style.display = 'block';
    } catch (e) {
        alert('Invalid Token: ' + e.message);
        resultArea.style.display = 'none';
    }
}

async function handleSignToken() {
    const signBtn = document.getElementById('sign-token-btn');
    if (!window.currentPayload) return;

    signBtn.disabled = true;
    signBtn.innerText = 'Signing...';

    // Canonicalize JSON (sort keys) so signature matches Rust's sorted expectation
    const canonicalize = (obj) => {
        if (Array.isArray(obj)) {
            return obj.map(canonicalize);
        } else if (typeof obj === 'object' && obj !== null) {
            const sorted = {};
            Object.keys(obj).sort().forEach(key => {
                sorted[key] = canonicalize(obj[key]);
            });
            return sorted;
        }
        return obj;
    };

    const payloadString = JSON.stringify(canonicalize(window.currentPayload));

    try {
        // 1. Sign
        const response = await fetch('/api/sign', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ payload: payloadString })
        });

        if (!response.ok) {
            throw new Error('Signing failed: ' + await response.text());
        }

        const signData = await response.json();

        // Construct Execution Request
        const executionRequest = {
            command: window.currentPayload,
            signature: signData.signature,
            id_token: signData.id_token,
            public_key: signData.public_key,
            timestamp_token: signData.timestamp_token
        };

        // Create Signed Token: Base64 Encoded JSON of ExecutionRequest
        const signedToken = btoa(JSON.stringify(executionRequest));

        document.getElementById('signed-token-output').value = signedToken;
        document.getElementById('signed-result-area').style.display = 'block';

        signBtn.innerText = 'Signed Successfully';
    } catch (err) {
        alert('Error: ' + err.message);
        signBtn.disabled = false;
        signBtn.innerText = 'Sign Command';
    }
}

async function handleExecuteToken() {
    const input = document.getElementById('signed-token-input');
    const btn = document.getElementById('execute-token-btn');
    const resultArea = document.getElementById('agent-result-area');

    if (!input.value.trim()) {
        alert('Please paste a token');
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Submitting...';

    try {
        const jsonStr = atob(input.value.trim());
        const executionRequest = JSON.parse(jsonStr);

        console.log('Sending execution request...');
        const agentResponse = await fetch('http://127.0.0.1:10022/execute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(executionRequest)
        });

        console.log('Agent response status:', agentResponse.status);

        if (agentResponse.ok) {
            const resData = await agentResponse.json();

            // Prioritize ID from agent response, fallback to payload
            const executionId = resData.message || (executionRequest.command && executionRequest.command.id);

            if (!executionId) {
                alert('Execution started, but no ID returned for monitoring.');
                return;
            }

            console.log('Execution started, redirecting to monitor:', executionId);
            // Redirect to Monitor Page
            window.location.href = `/ui/monitor?id=${executionId}`;

        } else {
            let errorMsg = `Server returned ${agentResponse.status}`;
            try {
                // Read text first to ensure we can log/display it even if JSON parse fails
                const textBody = await agentResponse.text();
                try {
                    const errorData = JSON.parse(textBody);
                    if (errorData && errorData.error) {
                        errorMsg = errorData.error;
                    } else if (textBody.trim()) {
                        // JSON but no 'error' field? Use full text.
                        errorMsg += `: ${textBody}`;
                    }
                } catch (jsonErr) {
                    // Not JSON, append text body if present
                    if (textBody.trim()) {
                        errorMsg += `: ${textBody}`;
                    }
                }
            } catch (readErr) {
                console.warn('Failed to read response body:', readErr);
            }
            throw new Error(errorMsg);
        }

    } catch (e) {
        console.error('Execution failed:', e);
        alert('Execution Error: ' + e.message);
    } finally {
        // Always re-enable button if we didn't redirect (redirect unloads page anyway)
        // Check if we are still on the page roughly (though redirect is async)
        // Simple timeout to allow redirect to happen? No, just re-enable.
        // If redirect happens, this doesn't matter.
        btn.disabled = false;
        btn.textContent = 'Execute';
    }
}

async function handleSignAndExecute() {

    const signBtn = document.getElementById('sign-btn');
    const commandInput = document.getElementById('command-input');
    const signatureOutput = document.getElementById('signature-output');

    const commandName = commandInput.value;
    if (!commandName) {
        alert('Please enter a command name');
        return;
    }

    signBtn.disabled = true;
    signBtn.innerText = 'Signing...';

    const executionId = crypto.randomUUID();
    const commandPayload = { command: commandName, id: executionId };
    const payloadString = JSON.stringify(commandPayload);

    try {
        // 1. Sign
        const response = await fetch('/api/sign', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ payload: payloadString })
        });

        if (!response.ok) {
            throw new Error('Signing failed: ' + await response.text());
        }

        const signData = await response.json();

        // Update hidden output if needed, or just proceed
        if (signatureOutput) signatureOutput.innerText = signData.signature;

        // 2. Execute
        signBtn.innerText = 'Executing...';

        const executionRequest = {
            command: commandPayload,
            signature: signData.signature,
            id_token: signData.id_token,
            public_key: signData.public_key,
            timestamp_token: signData.timestamp_token
        };

        const agentResponse = await fetch('http://127.0.0.1:10022/execute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(executionRequest)
        });

        if (agentResponse.ok) {
            // Success -> Redirect to Monitor page
            window.location.href = `/ui/monitor?id=${executionId}`;
        } else {
            const errorData = await agentResponse.json();
            alert(`Execution Error: ${errorData.error}`);
            signBtn.disabled = false;
            signBtn.innerText = 'Sign & Execute';
        }

    } catch (err) {
        alert(`Error: ${err.message}`);
        signBtn.disabled = false;
        signBtn.innerText = 'Sign & Execute';
    }
}

// Function to start streaming logs (called by execute.html)
function startStreaming(executionId) {
    const agentOutput = document.getElementById('agent-output');
    const statusArea = document.getElementById('status-area');
    const agentArea = document.getElementById('agent-result-area');

    agentArea.style.display = 'block';
    statusArea.innerText = `Streaming logs for Execution ID: ${executionId}`;

    const wsUrl = `ws://127.0.0.1:10022/stream/${executionId}`;
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        const info = document.createElement('div');
        info.textContent = `[Connected to stream]`;
        info.style.color = "#339af0";
        agentOutput.appendChild(info);
    };

    ws.onmessage = (event) => {
        const logLine = document.createElement('pre');
        logLine.style.margin = "0";
        logLine.style.padding = "0"; // compact
        logLine.style.border = "none";
        logLine.textContent = event.data;
        agentOutput.appendChild(logLine);
        agentOutput.scrollTop = agentOutput.scrollHeight;
    };

    ws.onclose = () => {
        const info = document.createElement('div');
        info.textContent = `[Stream finished]`;
        info.style.color = "gray";
        agentOutput.appendChild(info);
        statusArea.innerText = "Execution Finished";
    };

    ws.onerror = (e) => {
        const info = document.createElement('div');
        info.textContent = `[Connection Error]`;
        info.style.color = "red";
        agentOutput.appendChild(info);
    };
}
