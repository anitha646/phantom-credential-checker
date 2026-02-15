// Core Dashboard Logic
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const progressFill = document.getElementById('progressFill');
const threatFeed = document.getElementById('threatFeed');
const viewAllBtn = document.getElementById('viewAllBtn');
const consoleBody = document.getElementById('consoleBody');
const toastContainer = document.getElementById('toastContainer');
const reportSearch = document.getElementById('reportSearch');
const riskFilter = document.getElementById('riskFilter');

// Statistics
let stats = {
    interceptions: 0,
    redactions: 0,
    breaches: 0,
    totalScanned: 1284
};

// Initial state
document.addEventListener('DOMContentLoaded', () => {
    addFeedItem('System Initialized - Monitoring Active', 'success');
    startTelemetry();
    updateAnalyticsUI();

    // Request notification permission
    if ("Notification" in window) {
        Notification.requestPermission();
    }
});

// Click to upload
if (dropZone) {
    dropZone.addEventListener('click', () => fileInput.click());
}

// Drag and Drop Logic
if (dropZone) {
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, e => {
            e.preventDefault();
            e.stopPropagation();
        }, false);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.add('dragging'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragging'), false);
    });

    dropZone.addEventListener('drop', (e) => {
        handleFiles(e.dataTransfer.files);
    }, false);
}

if (fileInput) {
    fileInput.addEventListener('change', function () {
        handleFiles(this.files);
    });
}

function handleFiles(files) {
    if (files.length > 0) {
        const file = files[0];
        const reader = new FileReader();
        reader.onload = (e) => processWithBackend(file, e.target.result);
        reader.readAsText(file);
    }
}

async function processWithBackend(file, content) {
    if (!progressFill) return;

    progressFill.style.width = '20%';
    addFeedItem(`Analyzing: ${file.name}`);
    addConsoleLine(`[SCAN] Initializing analysis for payload: ${file.name}`);

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        });

        const data = await response.json();
        progressFill.style.width = '60%';

        if (data.success) {
            stats.interceptions++;
            stats.totalScanned++;
            const redactionCount = data.redaction_summary.total_redactions;
            stats.redactions += redactionCount;

            // Update UI
            document.getElementById('kpiInterceptions').textContent = stats.interceptions;
            document.getElementById('kpiRedactions').textContent = stats.redactions;
            updateAnalyticsUI();

            addFeedItem(`Scan Complete: ${redactionCount} items redacted`, redactionCount > 0 ? 'warning' : 'success');
            addConsoleLine(`[SUCCESS] Redaction engine processed ${redactionCount} nodes. Interception bridge active.`);

            // Trigger High Risk Alert if needed
            if (redactionCount > 5) {
                showToast('High Risk Detected', `${redactionCount} sensitive items found in ${file.name}`, 'high');
                triggerBrowserNotification('Critical Security Event', `Sensitive data leakage blocked in ${file.name}`);
            }

            // Map to redacted_content from backend
            const sanitizedText = data.redacted_content || data.safe_data || "No content returned from engine.";
            addHistoryRow(file.name, redactionCount > 0 ? 'Sensitive Data' : 'Clean', redactionCount, sanitizedText);

            // Add to archive table (mock)
            addArchiveRow(file.name, redactionCount);

            progressFill.style.width = '100%';
            setTimeout(() => progressFill.style.width = '0%', 1000);
        } else {
            addFeedItem(`Error: ${data.error}`, 'warning');
            addConsoleLine(`[FAIL] Backend error: ${data.error}`, 'danger');
            progressFill.style.width = '0%';
        }
    } catch (error) {
        addFeedItem('Network Error during scan', 'warning');
        addConsoleLine(`[CRITICAL] Network drop detected during interception.`, 'danger');
        progressFill.style.width = '0%';
    }
}

function addHistoryRow(filename, status, count, redactedContent) {
    const tbody = document.querySelector('.scan-table tbody');
    if (!tbody) return;

    const row = document.createElement('tr');
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const statusClass = count > 0 ? 'warning' : 'success';

    row.innerHTML = `
        <td><span>${filename}</span></td>
        <td><span class="status-badge ${statusClass}">${status}</span></td>
        <td>${count}</td>
        <td>${time}</td>
        <td class="row-actions">
            <button class="download-btn" title="Download Redacted">
                <svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor">
                    <path d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z"/>
                </svg>
            </button>
        </td>
    `;

    const btn = row.querySelector('.download-btn');
    btn.addEventListener('click', () => downloadFile(filename, redactedContent));

    tbody.insertBefore(row, tbody.firstChild);
}

function addArchiveRow(filename, count) {
    const tbody = document.querySelector('#archiveTable tbody');
    if (!tbody) return;

    const row = document.createElement('tr');
    const date = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + ', ' + new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    let risk = 'Low';
    let riskClass = 'low';
    if (count > 20) { risk = 'High'; riskClass = 'high'; }
    else if (count > 5) { risk = 'Medium'; riskClass = 'medium'; }

    row.innerHTML = `
        <td>${date}</td>
        <td>${filename}</td>
        <td><span class="risk-badge ${riskClass}">${risk}</span></td>
        <td>Secured</td>
        <td>${count}</td>
    `;
    tbody.insertBefore(row, tbody.firstChild);
}

function downloadFile(filename, content) {
    if (!content) {
        addFeedItem('Error: No content to download', 'warning');
        return;
    }
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename.split('.')[0] + '_redacted.txt';
    a.click();
    URL.revokeObjectURL(url);
    addFeedItem(`Exported: ${a.download}`, 'success');
}

function addFeedItem(message, type = 'default') {
    if (!threatFeed) return;
    const item = document.createElement('div');
    item.className = 'feed-item';
    const time = new Date().toLocaleTimeString([], { hour12: false });
    const dotType = type === 'warning' ? 'warning' : type === 'success' ? 'success' : 'purple';

    item.innerHTML = `
        <span class="feed-dot ${dotType}"></span>
        <span class="feed-time">[${time}]</span>
        <span class="feed-text">${message}</span>
    `;
    threatFeed.insertBefore(item, threatFeed.firstChild);
}

// Global Search & Filters
if (reportSearch) {
    reportSearch.addEventListener('input', applyFilters);
}
if (riskFilter) {
    riskFilter.addEventListener('change', applyFilters);
}

function applyFilters() {
    const query = reportSearch.value.toLowerCase();
    const risk = riskFilter.value.toLowerCase();
    const rows = document.querySelectorAll('#archiveTable tbody tr');

    rows.forEach(row => {
        const filename = row.cells[1].textContent.toLowerCase();
        const rowRisk = row.querySelector('.risk-badge').textContent.toLowerCase();

        const matchesSearch = filename.includes(query);
        const matchesRisk = risk === 'all' || rowRisk === risk;

        if (matchesSearch && matchesRisk) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

// Toast System
function showToast(title, message, type = 'info') {
    if (!toastContainer) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type === 'high' ? 'high-risk' : ''}`;

    toast.innerHTML = `
        <div class="toast-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2L1 21h22L12 2zm0 3.99L19.53 19H4.47L12 5.99zM11 16h2v2h-2v-2zm0-7h2v5h-2V9z"/>
            </svg>
        </div>
        <div class="toast-content">
            <div class="toast-title">${title}</div>
            <div class="toast-message">${message}</div>
        </div>
        <button class="toast-close">&times;</button>
    `;

    toastContainer.appendChild(toast);

    // Trigger animation
    setTimeout(() => toast.classList.add('show'), 100);

    // Auto remove
    const timeout = setTimeout(() => hideToast(toast), 5000);

    toast.querySelector('.toast-close').addEventListener('click', () => {
        clearTimeout(timeout);
        hideToast(toast);
    });
}

function hideToast(toast) {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
}

function triggerBrowserNotification(title, body) {
    if (Notification.permission === "granted") {
        new Notification(title, { body, icon: '/static/icon.png' });
    }
}

// Console Telemetry
function addConsoleLine(text, type = 'info') {
    if (!consoleBody) return;
    const line = document.createElement('div');
    line.className = 'console-line';
    if (type === 'danger') line.style.color = '#ef4444';
    line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
    consoleBody.appendChild(line);
    consoleBody.scrollTop = consoleBody.scrollHeight;
}

function startTelemetry() {
    setInterval(() => {
        const packets = Math.floor(Math.random() * 50) + 10;
        addConsoleLine(`[UDP] Packet bridge overhead: ${packets}ms — Interception stable.`);
    }, 8000);
}

function updateAnalyticsUI() {
    const el = document.getElementById('statTotalScanned');
    if (el) el.textContent = stats.totalScanned.toLocaleString();
}

// Navigation Logic
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        const targetView = item.getAttribute('data-view');
        if (!targetView) return;

        // Update active nav
        document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
        item.classList.add('active');

        // Update active view
        document.querySelectorAll('.view-container').forEach(view => view.classList.remove('active'));
        const targetEl = document.getElementById(targetView);
        if (targetEl) {
            targetEl.classList.add('active');
        }
    });
});

// View All History
if (viewAllBtn) {
    viewAllBtn.addEventListener('click', () => {
        // Toggle to Reports view
        document.querySelector('[data-view="reportsView"]').click();
    });
}
