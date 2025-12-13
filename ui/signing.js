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
});

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
                             <small class="text-secondary" style="font-size: 0.75rem;">${cmd.opa_rule}</small>
                             <a href="/ui/sign?cmd=${cmd.name}" class="btn btn-sm btn-outline-primary">Select</a>
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
            // Success -> Redirect to Execute/Monitor page
            window.location.href = `/ui/execute?id=${executionId}`;
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
