"use strict";

const API_URL = "http://127.0.0.1:8000";

let latestPredictions = [];
let latestEvents = [];
let latestFlows = [];
let apiReachable = false;
let captureHealth = "UNKNOWN";
let lastSuccessfulUpdate = null;
let activeView = "overview";
let lastHealthData = null;
let lastStatsData = null;
let lastFlowTotals = null;
let visibleAlertRows = [];
let latestHistoryRows = [];
let alertFeedbackByRecord = new Map();
let modelQualityLoaded = false;
let transferTrendSamples = [];
let baselineNotificationRecords = null;

/* =========================================================
   GENERAL HELPERS
========================================================= */

function safeNumber(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number : 0;
}

function clamp(value, min, max) {
    return Math.min(Math.max(value, min), max);
}

function escapeHTML(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function formatTime(timestamp) {
    if (!timestamp) return "--";

    const date = new Date(timestamp);

    return Number.isNaN(date.getTime())
        ? String(timestamp)
        : date.toLocaleTimeString();
}

function formatBytes(bytes) {
    bytes = Math.max(0, safeNumber(bytes));

    if (bytes < 1024) return `${bytes.toFixed(0)} B`;
    if (bytes < 1024 * 1024) {
        return `${(bytes / 1024).toFixed(1)} KB`;
    }
    if (bytes < 1024 * 1024 * 1024) {
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    }

    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function normalizeLabel(value) {
    return String(value ?? "").trim().toUpperCase();
}

function getEnforcementStatus(item) {
    const status = normalizeLabel(item?.enforcement_status);

    // Old records may not contain this field.
    return status || "UNKNOWN";
}

function getFirewallAction(item) {
    return normalizeLabel(item?.firewall_action) || "UNKNOWN";
}

function getPrediction(item) {
    return normalizeLabel(item?.prediction) || "UNKNOWN";
}

function getAttackProbability(item) {
    let probability = safeNumber(item?.attack_probability);

    // Support percentage-formatted data if the API provides it.
    if (probability > 1 && probability <= 100) {
        probability /= 100;
    }

    return clamp(probability, 0, 1);
}

/* =========================================================
   TRAFFIC DIRECTION AND SIZE
========================================================= */

function getTransferInfo(flow) {
    const direction = String(
        flow?.transfer_direction || "NO DATA"
    ).toUpperCase();

    const forwardBytes = safeNumber(flow?.forward_bytes);
    const backwardBytes = safeNumber(flow?.backward_bytes);
    const totalBytes = safeNumber(flow?.total_bytes);

    let transferBytes = totalBytes;
    let icon = "↕";
    let label = "Both directions";
    let className = "transfer-bidirectional";

    if (direction === "DOWNLOAD") {
        transferBytes = backwardBytes;
        icon = "↓";
        label = "Download from destination";
        className = "transfer-download";
    } else if (direction === "UPLOAD") {
        transferBytes = forwardBytes;
        icon = "↑";
        label = "Upload to destination";
        className = "transfer-upload";
    } else if (direction !== "BIDIRECTIONAL") {
        label = "No data yet";
        className = "transfer-none";
    }

    return {
        icon,
        label,
        size: formatBytes(transferBytes),
        className
    };
}

/* =========================================================
   TRAFFIC DONUT CHART
========================================================= */

function updateTrafficDonut(total, normal, attacks) {
    const donut = document.getElementById("trafficDonut");
    if (!donut) return;

    total = Math.max(0, safeNumber(total));
    normal = Math.max(0, safeNumber(normal));
    attacks = Math.max(0, safeNumber(attacks));

    const totalSafe = Math.max(total, 1);
    const normalAngle = (normal / totalSafe) * 360;

    donut.style.background = `
        conic-gradient(
            #20e39a 0deg ${normalAngle}deg,
            #ff4d5f ${normalAngle}deg 360deg
        )
    `;

    const donutTotal = document.getElementById("donutTotal");
    if (donutTotal) donutTotal.textContent = total;

    const normalPercent = document.getElementById("normalPercent");
    if (normalPercent) {
        normalPercent.textContent =
            `${((normal / totalSafe) * 100).toFixed(1)}%`;
    }

    const attackPercent = document.getElementById("attackPercent");
    if (attackPercent) {
        attackPercent.textContent =
            `${((attacks / totalSafe) * 100).toFixed(1)}%`;
    }
}

/* =========================================================
   ATTACK PROBABILITY CHART
========================================================= */

function updateRiskChart(predictions) {
    const container = document.getElementById("riskChart");
    if (!container) return;

    if (!Array.isArray(predictions) || predictions.length === 0) {
        container.innerHTML = `
            <div class="chart-empty">
                Waiting for prediction data...
            </div>
        `;
        return;
    }

    const values = predictions
        .slice()
        .reverse()
        .slice(-30)
        .map(item => getAttackProbability(item));

    if (values.length === 1) {
        values.push(values[0]);
    }

    const width = 700;
    const height = 150;

    const points = values.map((value, index) => {
        const x =
            (index / Math.max(values.length - 1, 1)) * width;

        const y = height - value * (height - 15) - 5;

        return `${x},${y}`;
    }).join(" ");

    const areaPoints = `0,${height} ${points} ${width},${height}`;

    container.innerHTML = `
        <svg
            class="risk-svg"
            viewBox="0 0 ${width} ${height}"
            preserveAspectRatio="none"
            role="img"
            aria-label="Attack probability history"
        >
            <defs>
                <linearGradient
                    id="riskFill"
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                >
                    <stop
                        offset="0%"
                        stop-color="#a855f7"
                        stop-opacity="0.35"
                    />
                    <stop
                        offset="100%"
                        stop-color="#a855f7"
                        stop-opacity="0"
                    />
                </linearGradient>
            </defs>

            <polygon
                points="${areaPoints}"
                fill="url(#riskFill)"
            />

            <polyline
                points="${points}"
                fill="none"
                stroke="#a855f7"
                stroke-width="3"
                stroke-linecap="round"
                stroke-linejoin="round"
            />
        </svg>
    `;
}

/* =========================================================
   DASHBOARD STATISTICS
========================================================= */

async function loadStats() {
    try {
        const response = await fetch(
            `${API_URL}/api/stats`,
            { cache: "no-store" }
        );

        if (!response.ok) {
            throw new Error("Failed to load statistics");
        }

        const data = await response.json();
        apiReachable = true;
        lastStatsData = data;
        updateSystemStatus();
        updateProtectionHealth();
        markDataFresh();

        const elements = {
            totalPredictions: data.total_predictions ?? 0,
            normalPredictions: data.normal_predictions ?? 0,
            attackPredictions: data.attack_predictions ?? 0,
            allowedCount: data.allowed ?? 0,
            monitoredCount: data.being_watched ?? data.monitored ?? 0,
            blockAttempts: data.block_attempts ?? 0,
            activeBlocks: data.active_blocks ?? 0,
            recoveredBlocks: data.recovered_blocks ?? 0,
            recoveryFailures: data.recovery_failures ?? 0,
            failedBlocks: data.failed_blocks ?? 0,
        };

        for (const [id, value] of Object.entries(elements)) {
            const element = document.getElementById(id);

            if (element) {
                element.textContent = value;
            }
        }

        const averageRisk = document.getElementById("averageRisk");

        if (averageRisk) {
            averageRisk.textContent =
                `${(
                    safeNumber(data.average_attack_probability) * 100
                ).toFixed(2)}%`;
        }

        const blockThreshold = document.getElementById("blockThreshold");
        if (blockThreshold) {
            blockThreshold.textContent = data.firewall_policy_status === "CONFIGURATION_ERROR"
                ? "Disabled"
                : `${(safeNumber(data.block_threshold) * 100).toFixed(0)}%`;
        }

        updateTrafficDonut(
            safeNumber(data.total_predictions),
            safeNumber(data.normal_predictions),
            safeNumber(data.attack_predictions)
        );

    } catch (error) {
        console.error("Statistics error:", error);
        apiReachable = false;
        lastStatsData = null;
        updateSystemStatus();
        updateProtectionHealth();
        markDataStale();
    }
}

function markDataFresh() {
    lastSuccessfulUpdate = new Date();
    const freshness = document.getElementById("dataFreshness");
    const label = document.getElementById("dataFreshnessLabel");
    if (freshness) freshness.classList.remove("is-stale");
    if (label) label.textContent = lastSuccessfulUpdate.toLocaleTimeString();
}

function markDataStale() {
    const freshness = document.getElementById("dataFreshness");
    const label = document.getElementById("dataFreshnessLabel");
    if (freshness) freshness.classList.add("is-stale");
    if (label) {
        label.textContent = lastSuccessfulUpdate
            ? `Stale · ${lastSuccessfulUpdate.toLocaleTimeString()}`
            : "No data";
    }
}

function updateSystemStatus() {
    const apiStatus = document.getElementById("apiStatus");
    const apiStatusDetail = document.getElementById("apiStatusDetail");
    const captureStatusDetail = document.getElementById("captureStatusDetail");
    const apiChip = document.querySelector(".api-status-chip");
    const captureChip = document.querySelector(".capture-status-chip");
    const apiDetailCard = document.querySelector(".status-detail.api-health");
    const captureDetailCard = document.querySelector(".status-detail.capture-health");
    const apiLabel = apiReachable ? "Connected" : "Offline";
    if (apiStatus) apiStatus.textContent = apiLabel;
    if (apiStatusDetail) apiStatusDetail.textContent = apiLabel;
    if (captureStatusDetail) {
        captureStatusDetail.textContent = captureHealth === "UNKNOWN"
            ? "Unknown"
            : captureHealth;
    }
    if (apiChip) apiChip.classList.toggle("status-error", !apiReachable);
    if (apiDetailCard) apiDetailCard.classList.toggle("status-error", !apiReachable);
    if (captureDetailCard) {
        captureDetailCard.classList.toggle(
            "status-error",
            captureHealth === "STALE" || captureHealth === "STOPPED"
        );
        captureDetailCard.classList.toggle("status-warning", captureHealth === "UNKNOWN");
    }
    if (captureChip) {
        captureChip.classList.toggle(
            "status-error",
            captureHealth === "STALE" || captureHealth === "STOPPED"
        );
        captureChip.classList.toggle(
            "status-warning",
            captureHealth === "UNKNOWN"
        );
    }
}

function updateProtectionHealth() {
    const banner = document.getElementById("protectionHealth");
    const title = document.getElementById("healthTitle");
    const message = document.getElementById("healthMessage");
    const symbol = document.getElementById("healthSymbol");
    if (!banner || !title || !message) return;

    const issues = [];
    if (!apiReachable) issues.push("Dashboard API is offline; current protection status cannot be confirmed.");
    if (captureHealth === "STOPPED") issues.push("Packet capture is stopped, so new traffic is not being collected.");
    else if (captureHealth === "STALE") issues.push("Packet capture heartbeat is stale; new traffic may not be reaching the dashboard.");
    else if (captureHealth === "UNKNOWN") issues.push("Packet capture status has not been confirmed.");

    const policyStatus = lastHealthData?.firewall_policy_status || lastStatsData?.firewall_policy_status;
    if (policyStatus === "CONFIGURATION_ERROR") {
        issues.push(lastHealthData?.firewall_policy_message || "Firewall threshold configuration needs attention.");
    }

    const failedRecoveries = safeNumber(lastStatsData?.recovery_failures);
    const failedBlocks = safeNumber(lastStatsData?.failed_blocks);
    if (failedRecoveries > 0) {
        issues.push(`${failedRecoveries} source${failedRecoveries === 1 ? " has" : "s have"} a failed automatic recovery; firewall status needs review.`);
    }
    if (failedBlocks > 0) {
        issues.push(`${failedBlocks} block attempt${failedBlocks === 1 ? "" : "s"} failed during this session. Those attempts are not counted as successful blocks.`);
    }

    const attentionNeeded = issues.length > 0;
    banner.classList.toggle("health-warning", attentionNeeded);
    banner.classList.toggle("health-ok", !attentionNeeded);
    if (symbol) symbol.textContent = attentionNeeded ? "!" : "✓";
    title.textContent = attentionNeeded ? "Protection needs attention" : "Protection checks look good";
    message.textContent = attentionNeeded
        ? issues.join(" ")
        : "Dashboard API is connected, packet capture is running, and no current firewall or recovery errors were reported.";
}

async function loadHealth() {
    try {
        const response = await fetch(`${API_URL}/api/health`, { cache: "no-store" });
        if (!response.ok) throw new Error("Health check failed");
        const health = await response.json();
        lastHealthData = health;
        captureHealth = normalizeLabel(health.capture?.status) || "UNKNOWN";
        const captureTopStatus = document.getElementById("captureTopStatus");
        if (captureTopStatus) captureTopStatus.textContent = captureHealth;
        updateSystemStatus();
        updateProtectionHealth();
    } catch (error) {
        lastHealthData = null;
        captureHealth = "UNKNOWN";
        const captureTopStatus = document.getElementById("captureTopStatus");
        if (captureTopStatus) captureTopStatus.textContent = "Unknown";
        updateSystemStatus();
        updateProtectionHealth();
    }
}

/* =========================================================
   EXPLAINABILITY HELPERS
========================================================= */

function getShortReason(item) {
    const action = getFirewallAction(item);
    const prediction = getPrediction(item);
    let explanation = item?.explanation;

    if (typeof explanation === "string") {
        try {
            explanation = JSON.parse(explanation);
        } catch {
            explanation = null;
        }
    }

    if (typeof explanation?.plain_reason === "string" && explanation.plain_reason.trim()) {
        if (prediction === "NORMAL" && (action === "BLOCK" || action === "MONITOR")) {
            return "The traffic did not look clearly harmful, but some activity still seemed unusual.";
        }
        return explanation.plain_reason.trim();
    }

    if (prediction === "ATTACK") {
        const influences = Array.isArray(explanation?.top_attack_influences)
            ? explanation.top_attack_influences
            : Array.isArray(explanation?.top_features)
                ? explanation.top_features.filter(feature =>
                    Number(feature?.shap_value ?? feature?.contribution) > 0
                )
                : [];
        const strongest = influences
            .slice()
            .sort((a, b) => Math.abs(Number(b.shap_value ?? b.contribution)) -
                Math.abs(Number(a.shap_value ?? a.contribution)))[0];
        const feature = strongest?.feature;
        const plainNames = {
            "Protocol": "the type of connection",
            "Network Protocol": "the type of connection",
            "Flow Duration": "how long the connection stayed open",
            "Connection Duration": "how long the connection stayed open",
            "Total Fwd Packets": "the number of messages sent",
            "Outgoing Packet Count": "the number of messages sent",
            "Total Backward Packets": "the number of replies received",
            "Incoming Packet Count": "the number of replies received",
            "Fwd Packets Length Total": "the amount of data sent",
            "Outgoing Data Volume": "the amount of data sent",
            "Bwd Packets Length Total": "the amount of data received",
            "Incoming Data Volume": "the amount of data received",
            "Flow Bytes/s": "how quickly data was sent",
            "Data Transfer Rate": "how quickly data was sent",
            "Flow Packets/s": "how often messages were sent",
            "Packet Transmission Rate": "how often messages were sent",
            "Packet Length Mean": "the size of the messages",
            "Average Packet Size": "the size of the messages",
            "Packet Length Std": "changes in message size",
            "Packet Size Variation": "changes in message size",
            "SYN Flag Count": "how the connection started",
            "TCP Connection-Start Flags": "how the connection started",
            "ACK Flag Count": "the pattern of replies",
            "TCP Acknowledgement Flags": "the pattern of replies",
            "RST Flag Count": "how the connection was reset",
            "TCP Connection-Reset Flags": "how the connection was reset",
            "FIN Flag Count": "how the connection was closed",
            "TCP Connection-Finish Flags": "how the connection was closed"
        };
        const phrase = plainNames[feature] || plainNames[strongest?.display_name];
        if (phrase) return `The system flagged this traffic mainly because of ${phrase}.`;
        return "The system noticed a pattern it associates with harmful traffic.";
    }

    if (prediction === "NORMAL") {
        if (action === "BLOCK" || action === "MONITOR") {
            return "The traffic did not look clearly harmful, but some activity still seemed unusual.";
        }
        return "The system did not find a strong attack pattern in this traffic.";
    }
    return "A simple explanation is not available for this record.";
}

function getEnforcementSummary(item) {
    const action = getFirewallAction(item);
    const status = getEnforcementStatus(item);

    if (action === "BLOCK" && status === "BLOCKED") return "Block placed";
    if (action === "BLOCK" && status === "FAILED") return "Block failed";
    if (action === "BLOCK" && status === "SIMULATED") return "Simulation only; no firewall rule was created";
    if (action === "BLOCK") return "Block result unknown";
    if (action === "MONITOR") return "Traffic is being watched";
    if (action === "ALLOW") return "Traffic was allowed";
    return "Result not available";
}

function getFriendlyFlowAction(action, status) {
    if (action === "BLOCK" && status === "BLOCKED") return "Block placed";
    if (action === "BLOCK" && status === "FAILED") return "Block failed";
    if (action === "BLOCK") return "Block not confirmed";
    if (action === "MONITOR") return "Watching";
    if (action === "ALLOW") return "Allowed";
    return "Waiting";
}

function getCurrentRuleSummary(item) {
    if (getFirewallAction(item) !== "BLOCK") return "No block in place";

    const state = normalizeLabel(item?.current_block_state);
    if (["SCHEDULED", "OBSERVING"].includes(normalizeLabel(item?.current_recovery_state))) {
        const due = new Date(item?.current_recovery_due_at);
        return Number.isNaN(due.getTime())
            ? "Block active; watching for a quiet period before recovery"
            : `Block active; quiet-period check ends around ${due.toLocaleTimeString()}`;
    }
    if (normalizeLabel(item?.current_recovery_state) === "FAILED") {
        if (state === "ACTIVE") return "Monitoring failed; block was kept in place";
        return "Could not confirm whether the block was removed";
    }
    if (state === "ACTIVE") return "Block was placed; no removal is recorded";
    if (state === "RECOVERED") return "Block was removed; it is no longer active";
    if (getEnforcementStatus(item) === "FAILED") return "No block was placed";
    return "Block status not confirmed";
}

function getFirewallReason(item) {
    const savedReason = String(item?.firewall_reason || "").trim();
    const action = getFirewallAction(item);
    const reason = savedReason.toLowerCase();
    if (reason.includes("protected") || reason.includes("trusted")) {
        return "This source is protected from automatic blocking, so it is being watched.";
    }
    if (reason.includes("misconfigured")) {
        return "A protection setting needs attention, so the traffic is being watched safely.";
    }
    if (action === "BLOCK" && reason.includes("immediate")) {
        const score = getAttackProbability(item) * 100;
        let threshold = safeNumber(item?.block_threshold) * 100;
        if (threshold > 100) threshold = 100;
        if (threshold > 0) {
            return `The model's threat score was ${score.toFixed(0)}%, above the ${threshold.toFixed(0)}% block limit, so the firewall placed a rule.`;
        }
        return "The model's threat score crossed the block limit, so the firewall placed a rule.";
    }
    if (action === "BLOCK") {
        const count = savedReason.match(/\((\d+)\)/)?.[1];
        return count
            ? `The source was flagged as suspicious ${count} times, so the firewall placed a rule.`
            : "The source was flagged repeatedly, so the firewall placed a rule.";
    }
    if (action === "MONITOR") {
        return "The threat score reached the watch level but not the block limit, so the connection is being watched.";
    }
    if (action === "ALLOW") {
        return "The threat score stayed below the watch and block limits, so the traffic was allowed.";
    }
    return "No further reason is available.";
}

function getFriendlyTrafficLabel(prediction) {
    if (prediction === "ATTACK") return "Possible threat detected";
    if (prediction === "NORMAL") return "Looks normal";
    return "Not available";
}

function getFriendlyActionLabel(action) {
    if (action === "BLOCK") return "Block chosen";
    if (action === "MONITOR") return "Watch";
    if (action === "ALLOW") return "Allow";
    return "Not available";
}

/* =========================================================
   EXPLAINABILITY PANEL
========================================================= */

function renderExplainability(predictions) {
    const container = document.getElementById("explainabilityContent");
    if (!container) return;

    const records = Array.isArray(predictions) ? predictions : [];
    const selected = records.find(item => getPrediction(item) === "ATTACK") || records[0];
    if (!selected) {
        container.innerHTML = '<p class="explainability-empty">No traffic decision is available yet.</p>';
        return;
    }

    const prediction = getPrediction(selected);
    const action = getFirewallAction(selected);
    const status = getEnforcementSummary(selected);
    const currentRule = getCurrentRuleSummary(selected);
    const reason = getShortReason(selected);
    const firewallReason = getFirewallReason(selected);
    const enforcementStatus = getEnforcementStatus(selected);
    const latestAlertTag = document.getElementById("latestAlertTag");
    if (latestAlertTag) {
        latestAlertTag.textContent = prediction === "ATTACK" ? "LATEST POSSIBLE THREAT" : "LATEST CHECK";
        latestAlertTag.classList.remove("test-sample-tag");
    }
    const actionClass = action === "BLOCK"
        ? enforcementStatus === "BLOCKED"
            ? "action-block"
            : enforcementStatus === "FAILED"
                ? "action-failed"
                : "action-monitor"
        : action === "ALLOW" ? "action-allow" : "action-monitor";

    container.innerHTML = `
        <div class="decision-summary">
            <div class="decision-status-row">
                <span><small>Traffic check</small><strong>${escapeHTML(getFriendlyTrafficLabel(prediction))}</strong></span>
                <span><small>Action</small><strong class="${actionClass}">${escapeHTML(getFriendlyActionLabel(action))}</strong></span>
                <span><small>What happened</small><strong>${escapeHTML(status)}</strong></span>
                <span><small>Block status</small><strong>${escapeHTML(currentRule)}</strong></span>
            </div>
            <p class="plain-reason"><strong>Why it was flagged:</strong><br>${escapeHTML(reason)}</p>
            <p><strong>Why this action:</strong> ${escapeHTML(firewallReason)}</p>
        </div>
    `;
}

function renderOverviewAlert(predictions) {
    const title = document.getElementById("overviewAlertTitle");
    const time = document.getElementById("overviewAlertTime");
    const tag = document.getElementById("overviewAlertTag");
    const content = document.getElementById("overviewAlertContent");
    if (!title || !time || !tag || !content) return;
    const card = content.closest(".overview-alert-card");

    const alert = (Array.isArray(predictions) ? predictions : [])
        .find(item => getPrediction(item) === "ATTACK");
    if (!alert) {
        card?.classList.remove("has-alert");
        title.textContent = "Latest threat and firewall result";
        time.textContent = "No threat alert recorded this session";
        tag.textContent = "No alerts";
        tag.className = "overview-alert-tag is-clear";
        content.innerHTML = '<p class="overview-no-alert">When an attack is detected, its prediction and firewall result will appear here.</p>';
        return;
    }

    card?.classList.add("has-alert");
    const action = getFirewallAction(alert);
    const enforcement = getEnforcementStatus(alert);
    const actionClass = action === "BLOCK"
        ? enforcement === "BLOCKED" ? "action-block" : enforcement === "FAILED" ? "action-failed" : "action-monitor"
        : action === "ALLOW" ? "action-allow" : "action-monitor";
    title.textContent = "Latest possible threat";
    time.textContent = `${formatTime(alert.timestamp)} · ${alert.source_ip || "Unknown source"} → ${alert.destination_ip || "Unknown destination"}`;
    tag.textContent = "ALERT";
    tag.className = "overview-alert-tag";
    content.innerHTML = `
        <div class="overview-alert-facts">
            <div><small>Model prediction</small><strong>Possible threat · ${(getAttackProbability(alert) * 100).toFixed(0)}% estimate</strong></div>
            <div><small>Firewall action</small><strong class="${actionClass}">${escapeHTML(getFriendlyActionLabel(action))}</strong></div>
            <div><small>Enforcement result</small><strong>${escapeHTML(getEnforcementSummary(alert))}</strong></div>
            <div><small>Current block status</small><strong>${escapeHTML(getCurrentRuleSummary(alert))}</strong></div>
        </div>
    `;
}
/* =========================================================
   LOAD PREDICTIONS
========================================================= */

async function loadPredictions() {
    try {
        const response = await fetch(
            `${API_URL}/api/predictions`,
            { cache: "no-store" }
        );

        if (!response.ok) {
            throw new Error("Failed to load predictions");
        }

        const data = await response.json();

        latestPredictions = Array.isArray(data.predictions)
            ? data.predictions
            : [];
        latestEvents = Array.isArray(data.events) ? data.events : [];

        checkForNewThreats(latestPredictions);

        updateRiskChart(latestPredictions);
        renderExplainability(latestPredictions);
        renderOverviewAlert(latestPredictions);
        renderRecoveryStatus(latestPredictions, latestEvents);
        renderAdaptationHistory([...latestPredictions, ...latestEvents]);

        const attacks = latestPredictions.filter(item =>
            getPrediction(item) === "ATTACK"
        );

        const navAlertCount = document.getElementById("navAlertCount");
        if (navAlertCount) {
            navAlertCount.textContent = attacks.length;
        }

        const alertBadge = document.getElementById("alertBadge");
        if (alertBadge) {
            alertBadge.textContent = attacks.length;
        }

        updateAlerts(attacks);

    } catch (error) {
        console.error("Prediction error:", error);
    }
}

/* =========================================================
   LOAD ACTIVE FLOWS
========================================================= */

async function loadFlows() {
    try {
        const response = await fetch(
            `${API_URL}/api/flows`,
            { cache: "no-store" }
        );

        if (!response.ok) {
            throw new Error("Failed to load network flows");
        }

        const data = await response.json();

        latestFlows = Array.isArray(data.flows)
            ? data.flows
            : [];

        updateFlowTotals(latestFlows);
        updateFlowTable(latestFlows);

        const recordCount = document.getElementById("recordCount");
        if (recordCount) {
            recordCount.textContent =
                `${latestFlows.length} active flows`;
        }

    } catch (error) {
        console.error("Flow error:", error);

        latestFlows = [];
        updateFlowTable([]);
    }
}

function updateFlowTotals(flows) {
    const sent = (Array.isArray(flows) ? flows : []).reduce(
        (total, flow) => total + Math.max(0, safeNumber(flow.forward_bytes)),
        0
    );
    const received = (Array.isArray(flows) ? flows : []).reduce(
        (total, flow) => total + Math.max(0, safeNumber(flow.backward_bytes)),
        0
    );
    const sentElement = document.getElementById("sentTotal");
    const receivedElement = document.getElementById("receivedTotal");
    const rateElement = document.getElementById("transferRate");
    if (sentElement) sentElement.textContent = formatBytes(sent);
    if (receivedElement) receivedElement.textContent = formatBytes(received);

    const now = Date.now();
    let rateText = "Calculating…";
    let sentRate = null;
    let receivedRate = null;
    if (lastFlowTotals) {
        const elapsed = (now - lastFlowTotals.time) / 1000;
        if (sent < lastFlowTotals.sent || received < lastFlowTotals.received) {
            rateText = "Recalculating…";
        } else if (elapsed > 0) {
            sentRate = (sent - lastFlowTotals.sent) / elapsed;
            receivedRate = (received - lastFlowTotals.received) / elapsed;
            rateText = `${formatBytes(sentRate + receivedRate)}/s`;
        }
    }
    if (rateElement) rateElement.textContent = rateText;
    lastFlowTotals = { sent, received, time: now };

    if (sentRate !== null && receivedRate !== null) {
        transferTrendSamples.push({ sent: sentRate, received: receivedRate, time: now });
        if (transferTrendSamples.length > 60) transferTrendSamples.shift();
        updateTransferTrendChart();
    }
}

function updateTransferTrendChart() {
    const container = document.getElementById("transferTrendChart");
    if (!container) return;
    if (transferTrendSamples.length < 2) {
        container.innerHTML = '<div class="chart-empty">Collecting transfer samples…</div>';
        return;
    }

    const width = 800;
    const height = 170;
    const insetX = 8;
    const insetY = 10;
    const maxRate = Math.max(
        1,
        ...transferTrendSamples.flatMap(sample => [sample.sent, sample.received])
    );
    const point = (value, index) => {
        const x = insetX + (index / (transferTrendSamples.length - 1)) * (width - insetX * 2);
        const y = height - insetY - (value / (maxRate * 1.1)) * (height - insetY * 2);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
    };
    const sentPoints = transferTrendSamples.map((sample, index) => point(sample.sent, index)).join(" ");
    const receivedPoints = transferTrendSamples.map((sample, index) => point(sample.received, index)).join(" ");
    container.innerHTML = `
        <svg class="risk-svg" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="Recent upload and download transfer rates">
            <polyline points="${sentPoints}" fill="none" stroke="#52d4e7" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" />
            <polyline points="${receivedPoints}" fill="none" stroke="#35dda0" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
    `;
}

/* =========================================================
   ACTIVE FLOW TABLE
========================================================= */

function updateFlowTable(flows) {
    const table = document.getElementById("predictionTable");
    if (!table) return;

    const search = (document.getElementById("flowSearch")?.value || "")
        .trim()
        .toLowerCase();
    const selectedFilter = document.getElementById("flowFilter")?.value || "all";

    if (!Array.isArray(flows) || flows.length === 0) {
        table.innerHTML = `
            <tr>
                <td colspan="8" class="empty">
                    No active network flows
                </td>
            </tr>
        `;
        return;
    }

    const filteredFlows = flows
        .slice()
        .reverse()
        .filter(flow => {
            const match = latestPredictions.find(prediction =>
                prediction.source_ip === flow.source_ip &&
                prediction.destination_ip === flow.destination_ip
            );
            const prediction = match ? getPrediction(match) : "ANALYZING";
            const transfer = getTransferInfo(flow);
            const searchable = [
                flow.source_ip,
                flow.source_port,
                flow.destination_ip,
                flow.destination_port,
                flow.protocol,
                transfer.label,
                transfer.size,
                prediction,
                match ? getFirewallAction(match) : "WAITING"
            ].join(" ").toLowerCase();
            return (!search || searchable.includes(search)) &&
                (selectedFilter === "all" || prediction === selectedFilter);
        });

    table.innerHTML = "";
    if (filteredFlows.length === 0) {
        table.innerHTML = '<tr><td colspan="8" class="empty">No connections match your search or filter.</td></tr>';
        return;
    }

    filteredFlows
        .slice(0, 15)
        .forEach(flow => {
            const row = document.createElement("tr");

            const matchingPrediction = latestPredictions.find(
                prediction =>
                    prediction.source_ip === flow.source_ip &&
                    prediction.destination_ip === flow.destination_ip
            );

            let prediction = "ANALYZING";
            let action = "WAITING";
            let enforcementStatus = "UNKNOWN";

            if (matchingPrediction) {
                prediction = getPrediction(matchingPrediction);
                action = getFirewallAction(matchingPrediction);
                enforcementStatus = getEnforcementStatus(matchingPrediction);
            }

            const transfer = getTransferInfo(flow);
            const transferDetail = transfer.label === "Both directions"
                ? `Sent ${formatBytes(flow.forward_bytes)} · received ${formatBytes(flow.backward_bytes)}`
                : `${transfer.label} · ${transfer.size}`;
            const sourceAddress = `${flow.source_ip || "--"}:${flow.source_port || "--"}`;
            const destinationAddress = `${flow.destination_ip || "--"}:${flow.destination_port || "--"}`;

            const predictionClass = prediction === "ATTACK"
                ? "badge-attack"
                : prediction === "NORMAL"
                    ? "badge-normal"
                    : "";

            let actionClass = "action-monitor";

            if (action === "ALLOW") {
                actionClass = "action-allow";
            } else if (
                action === "BLOCK" &&
                enforcementStatus === "BLOCKED"
            ) {
                actionClass = "action-block";
            } else if (
                action === "BLOCK" &&
                enforcementStatus === "FAILED"
            ) {
                actionClass = "action-failed";
            } else if (action === "MONITOR") {
                actionClass = "action-monitor";
            }

            row.innerHTML = `
                <td>${escapeHTML(sourceAddress)}</td>
                <td>${escapeHTML(destinationAddress)}</td>

                <td>
                    <span class="protocol">
                        ${escapeHTML(flow.protocol || "--")}
                    </span>
                </td>

                <td>
                    <span class="transfer-value ${escapeHTML(transfer.className)}" title="Captured network bytes, not a file name">
                        <span>${escapeHTML(transfer.icon)}</span>
                        <strong>${escapeHTML(transfer.size)}</strong>
                    </span>
                    <small class="table-subtext">${escapeHTML(transferDetail)}</small>
                    <details class="flow-details">
                        <summary>Connection details</summary>
                        <div>
                            <p><span>Source</span><strong>${escapeHTML(sourceAddress)}</strong></p>
                            <p><span>Destination</span><strong>${escapeHTML(destinationAddress)}</strong></p>
                            <p><span>Sent from source</span><strong>${formatBytes(flow.forward_bytes)}</strong></p>
                            <p><span>Received from destination</span><strong>${formatBytes(flow.backward_bytes)}</strong></p>
                            <p><span>Packets</span><strong>${safeNumber(flow.forward_packets)} sent · ${safeNumber(flow.backward_packets)} received</strong></p>
                        </div>
                    </details>
                </td>

                <td>${safeNumber(flow.total_packets)}</td>
                <td>${safeNumber(flow.duration)}s</td>

                <td>
                    <span class="badge ${predictionClass}">
                        ${escapeHTML(getFriendlyTrafficLabel(prediction))}
                    </span>
                    ${matchingPrediction ? `<small class="table-subtext">Threat estimate ${Math.round(getAttackProbability(matchingPrediction) * 100)}%</small>` : ""}
                </td>

                <td>
                    <span class="${actionClass}">
                        ${escapeHTML(getFriendlyFlowAction(action, enforcementStatus))}
                    </span>
                </td>
            `;

            table.appendChild(row);
        });
}

/* =========================================================
   RECENT ATTACK ALERTS
========================================================= */

function updateAlerts(attacks) {
    const container = document.getElementById("recentAlerts");
    if (!container) return;

    const search = (document.getElementById("alertSearch")?.value || "")
        .trim()
        .toLowerCase();
    const selectedFilter = document.getElementById("alertFilter")?.value || "all";
    visibleAlertRows = (Array.isArray(attacks) ? attacks : []).filter(alert => {
        const status = getEnforcementStatus(alert);
        const action = getFirewallAction(alert);
        const searchText = [
            alert.timestamp, alert.source_ip, alert.destination_ip,
            alert.prediction, action, status, getEnforcementSummary(alert),
            getShortReason(alert)
        ].join(" ").toLowerCase();
        const matchesFilter = selectedFilter === "all" ||
            (selectedFilter === "blocked" && status === "BLOCKED") ||
            (selectedFilter === "failed" && status === "FAILED") ||
            (selectedFilter === "unknown" && action === "BLOCK" && !["BLOCKED", "FAILED", "SIMULATED"].includes(status)) ||
            (selectedFilter === "monitor" && action === "MONITOR");
        return matchesFilter && (!search || searchText.includes(search));
    });

    const count = document.getElementById("alertHistoryCount");
    if (count) {
        const shown = Math.min(visibleAlertRows.length, 50);
        count.textContent = visibleAlertRows.length > 50
            ? `Showing ${shown} of ${visibleAlertRows.length} matching alerts · export to save all`
            : `${visibleAlertRows.length} matching alert${visibleAlertRows.length === 1 ? "" : "s"}`;
    }

    if (visibleAlertRows.length === 0) {
        container.innerHTML = '<div class="empty-alert">No alerts match this search or filter.</div>';
        return;
    }

    container.innerHTML = "";
    visibleAlertRows.slice(0, 50).forEach(alert => {
        const risk = (getAttackProbability(alert) * 100).toFixed(0);
        const feedback = alertFeedbackByRecord.get(String(alert.record_id || ""));
        const item = document.createElement("div");
        item.className = "alert-item";
        item.innerHTML = `
            <div class="alert-item-heading">
                <strong>Possible threat</strong>
                <time>${escapeHTML(formatTime(alert.timestamp))}</time>
            </div>
            <span>${escapeHTML(alert.source_ip || "Unknown source")} → ${escapeHTML(alert.destination_ip || "Unknown destination")} · Threat estimate ${risk}%</span>
            <small>${escapeHTML(getEnforcementSummary(alert))}</small>
            <p class="plain-reason">${escapeHTML(getShortReason(alert))}</p>
            <div class="feedback-row">
                <span>${feedback ? `Your review: ${feedback === "FALSE_ALARM" ? "Looks like normal traffic" : "Confirmed threat"}` : "Was this alert helpful?"}</span>
                <button class="feedback-button ${feedback === "FALSE_ALARM" ? "selected" : ""}" type="button" data-record-id="${escapeHTML(alert.record_id || "")}" data-feedback-value="FALSE_ALARM" ${feedback === "FALSE_ALARM" ? "disabled" : ""}>False alarm</button>
                <button class="feedback-button ${feedback === "CONFIRMED_THREAT" ? "selected" : ""}" type="button" data-record-id="${escapeHTML(alert.record_id || "")}" data-feedback-value="CONFIRMED_THREAT" ${feedback === "CONFIRMED_THREAT" ? "disabled" : ""}>Confirmed threat</button>
            </div>
        `;
        container.appendChild(item);
    });
}

async function loadAlertFeedback() {
    try {
        const response = await fetch(`${API_URL}/api/feedback`, { cache: "no-store" });
        if (!response.ok) throw new Error("Could not load saved alert reviews.");
        const data = await response.json();
        alertFeedbackByRecord = new Map((data.feedback || []).map(row => [
            String(row.record_id || ""),
            row.feedback
        ]));
        updateAlerts(latestPredictions.filter(item => getPrediction(item) === "ATTACK"));
    } catch (error) {
        console.warn("Alert feedback is unavailable:", error);
    }
}

async function submitAlertFeedback(button) {
    const recordId = button.dataset.recordId;
    const alert = latestPredictions.find(row => String(row.record_id || "") === recordId);
    if (!alert) return;

    const message = document.getElementById("feedbackMessage");
    const buttons = document.querySelectorAll(`.feedback-button[data-record-id="${CSS.escape(recordId)}"]`);
    buttons.forEach(item => { item.disabled = true; });
    if (message) message.textContent = "Saving your review…";
    try {
        const response = await fetch(`${API_URL}/api/feedback`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                record_id: recordId,
                record_timestamp: alert.timestamp,
                source_ip: alert.source_ip,
                destination_ip: alert.destination_ip,
                feedback: button.dataset.feedbackValue
            })
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.detail || "Could not save this review.");
        alertFeedbackByRecord.set(recordId, result.feedback);
        if (message) message.textContent = "Review saved locally. It does not change or retrain the model.";
        updateAlerts(latestPredictions.filter(item => getPrediction(item) === "ATTACK"));
    } catch (error) {
        if (message) message.textContent = error.message;
        buttons.forEach(item => { item.disabled = false; });
    }
}

function csvValue(value) {
    let text = String(value ?? "");
    if (/^[=+@\-\t\r]/.test(text)) text = `'${text}`;
    return `"${text.replace(/"/g, '""')}"`;
}

function exportAlertHistory() {
    const columns = [
        ["Timestamp", row => row.timestamp],
        ["Source IP", row => row.source_ip],
        ["Destination IP", row => row.destination_ip],
        ["Prediction", row => row.prediction],
        ["Threat estimate", row => `${(getAttackProbability(row) * 100).toFixed(1)}%`],
        ["Firewall action", row => row.firewall_action],
        ["Enforcement status", row => getEnforcementStatus(row)],
        ["Human review", row => alertFeedbackByRecord.get(String(row.record_id || "")) || ""],
        ["Reason", row => getShortReason(row)],
        ["Firewall reason", row => row.firewall_reason]
    ];
    const csv = [
        columns.map(([name]) => csvValue(name)).join(","),
        ...visibleAlertRows.map(row => columns.map(([, get]) => csvValue(get(row))).join(","))
    ].join("\r\n");
    const url = URL.createObjectURL(new Blob(["\uFEFF", csv], { type: "text/csv;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `sentinelai-alert-history-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function renderRecoveryStatus(predictions, events) {
    const container = document.getElementById("recoveryLiveStatus");
    if (!container) return;
    const watching = new Map();
    (Array.isArray(predictions) ? predictions : []).forEach(row => {
        if (
            row.current_block_state === "ACTIVE" &&
            row.current_recovery_state === "OBSERVING" &&
            row.source_ip
        ) watching.set(row.source_ip, row);
    });

    const activeRows = Array.from(watching.values());
    if (activeRows.length) {
        container.innerHTML = `
            <div class="recovery-status-banner is-watching"><span class="recovery-status-dot"></span><div><strong>Watching ${activeRows.length} blocked source${activeRows.length === 1 ? "" : "s"}</strong><p>The block stays active until the quiet period completes with no newly detected suspicious activity.</p></div></div>
            <div class="recovery-observation-list">${activeRows.slice(0, 5).map(row => `
                <div class="recovery-observation-row"><span><small>Blocked source</small><strong>${escapeHTML(row.source_ip)}</strong></span><span><small>Quiet period ends in</small><strong class="recovery-countdown" data-recovery-due="${escapeHTML(row.current_recovery_due_at || "")}">Calculating…</strong></span><span><small>Block state</small><strong class="action-block">Still active</strong></span></div>
            `).join("")}</div>
        `;
        updateRecoveryCountdowns();
        return;
    }

    const lifecycleActions = new Set(["RECOVERY_SCHEDULED", "RECOVERY_EXTENDED", "UNBLOCK", "RECOVERY_FAILED"]);
    const latest = (Array.isArray(events) ? events : [])
        .filter(row => lifecycleActions.has(normalizeLabel(row.firewall_action)))
        .sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)))[0];
    if (latest && normalizeLabel(latest.firewall_action) === "UNBLOCK") {
        const quietPeriodCompleted = Number(latest.event_details?.quiet_period_seconds) > 0;
        container.innerHTML = `<div class="recovery-status-banner is-recovered"><span class="recovery-status-dot"></span><div><strong>${quietPeriodCompleted ? "Block removed after the quiet period" : "Block removed"}</strong><p>${escapeHTML(latest.enforcement_message || (quietPeriodCompleted ? "No suspicious activity was observed during the configured quiet period." : "The firewall rule was removed."))}</p></div></div>`;
        return;
    }
    if (latest && normalizeLabel(latest.firewall_action) === "RECOVERY_FAILED") {
        container.innerHTML = `<div class="recovery-status-banner is-held"><span class="recovery-status-dot"></span><div><strong>Block kept in place</strong><p>${escapeHTML(latest.enforcement_message || "Monitoring could not confirm a safe quiet period.")}</p></div></div>`;
        return;
    }
    container.innerHTML = '<p class="empty-alert">No blocks are currently under recovery observation.</p>';
}

function updateRecoveryCountdowns() {
    document.querySelectorAll(".recovery-countdown[data-recovery-due]").forEach(element => {
        const due = Date.parse(element.dataset.recoveryDue);
        if (!Number.isFinite(due)) {
            element.textContent = "Waiting for a valid timer";
            return;
        }
        const remaining = Math.max(0, Math.ceil((due - Date.now()) / 1000));
        const minutes = Math.floor(remaining / 60);
        const seconds = remaining % 60;
        const hours = Math.floor(minutes / 60);
        element.textContent = hours
            ? `${hours}:${String(minutes % 60).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`
            : `${minutes}:${String(seconds).padStart(2, "0")}`;
    });
}

function renderAdaptationHistory(events) {
    const container = document.getElementById("adaptationHistory");
    if (!container) return;
    const labels = {
        RECOVERY_SCHEDULED: "Observation started",
        RECOVERY_EXTENDED: "Suspicious activity found · timer restarted",
        UNBLOCK: "Block removed after quiet period",
        RECOVERY_FAILED: "Block kept in place"
    };
    const items = (Array.isArray(events) ? events : [])
        .filter(row => row.prediction === "SYSTEM" && labels[normalizeLabel(row.firewall_action)])
        .sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)))
        .slice(0, 10);
    if (!items.length) {
        container.innerHTML = '<div class="empty-alert">No recent recovery activity.</div>';
        return;
    }
    container.innerHTML = items.map(row => {
        const action = normalizeLabel(row.firewall_action);
        const dueAt = row.event_details?.due_at;
        const detail = action === "RECOVERY_SCHEDULED" && dueAt
            ? `Watching for ${row.event_details?.duration_seconds || "the saved"} seconds. If no suspicious activity is detected and capture stays healthy, recovery is due around ${formatTime(dueAt)}.`
            : row.enforcement_message || "No additional recovery details were recorded.";
        return `
            <article class="history-item">
                <span class="history-marker"></span>
                <div class="history-item-main">
                    <div class="history-item-top"><strong>${escapeHTML(labels[action])}</strong><time>${escapeHTML(formatTime(row.timestamp))}</time></div>
                    <p>${escapeHTML(detail)}</p>
                    <small>${escapeHTML(row.source_ip || "Unknown source")} · ${escapeHTML(normalizeLabel(row.enforcement_status) || "Status unknown")}</small>
                </div>
            </article>
        `;
    }).join("");
}

function friendlyHistoryAction(action) {
    return ({ ALLOW: "Allow", MONITOR: "Watch", BLOCK: "Block" })[action] || action;
}

function percentText(value) {
    return `${(safeNumber(value) * 100).toFixed(1)}%`;
}

async function loadModelQuality(force = false) {
    if (modelQualityLoaded && !force) return;
    const state = document.getElementById("modelQualityState");
    const content = document.getElementById("modelQualityContent");
    if (!state || !content) return;
    state.textContent = "Loading the saved evaluation report…";
    state.classList.remove("quality-error");
    content.hidden = true;

    try {
        const response = await fetch(
            `${API_URL}/api/model-quality${force ? "?refresh=true" : ""}`,
            { cache: "no-store" }
        );
        if (!response.ok) throw new Error("Could not load model evaluation.");
        const data = await response.json();
        modelQualityLoaded = true;
        if (!data.available || !data.report) {
            state.classList.add("quality-error");
            state.innerHTML = `<strong>Model quality results are unavailable</strong><p>${escapeHTML(data.message || "A matching held-out evaluation could not be calculated.")}</p>`;
            return;
        }

        const report = data.report;
        const metrics = report.metrics || {};
        document.getElementById("qualityRecall").textContent = percentText(metrics.recall);
        document.getElementById("qualityFalseAlarm").textContent = percentText(metrics.false_positive_rate);
        document.getElementById("qualityMissed").textContent = percentText(metrics.missed_attack_rate);
        document.getElementById("qualitySamples").textContent = safeNumber(report.held_out_samples).toLocaleString();
        document.getElementById("qualityAccuracy").textContent = percentText(metrics.accuracy);
        document.getElementById("qualityPrecision").textContent = percentText(metrics.precision);
        document.getElementById("qualityF1").textContent = percentText(metrics.f1);
        const evaluatedAt = new Date(report.evaluated_at);
        document.getElementById("qualityDate").textContent = Number.isNaN(evaluatedAt.getTime())
            ? String(report.evaluated_at || "Not available")
            : evaluatedAt.toLocaleString();

        const matrix = report.confusion_matrix || [[0, 0], [0, 0]];
        const matrixValues = [
            ["Normal correctly recognized", matrix[0]?.[0]],
            ["Normal flagged as threat", matrix[0]?.[1]],
            ["Attacks missed", matrix[1]?.[0]],
            ["Attacks detected", matrix[1]?.[1]]
        ];
        document.getElementById("qualityConfusion").innerHTML = matrixValues.map(([label, value]) =>
            `<div><span>◈</span><label>${escapeHTML(label)}</label><strong>${safeNumber(value).toLocaleString()}</strong></div>`
        ).join("");

        const families = Object.entries(report.attack_family_recall || {});
        const familyContainer = document.getElementById("qualityFamilies");
        familyContainer.innerHTML = families.length
            ? `<div class="family-row family-heading"><span>Attack type</span><span>Detected</span><span>Recall</span></div>${families.map(([name, result]) => `<div class="family-row"><span>${escapeHTML(name)}</span><span>${safeNumber(result.detected)}/${safeNumber(result.total)}</span><strong>${percentText(result.recall)}</strong></div>`).join("")}`
            : '<p class="family-empty">No labeled attack types in this evaluation.</p>';

        const thresholds = Array.isArray(report.block_threshold_tradeoffs)
            ? report.block_threshold_tradeoffs
            : [];
        document.getElementById("qualityThresholds").innerHTML = thresholds.length
            ? `<div class="threshold-row threshold-heading"><span>Threshold</span><span>False blocks</span><span>Attacks not blocked</span></div>${thresholds.map(item => `<div class="threshold-row ${Number(item.threshold) === Number(report.block_threshold) ? "current-threshold" : ""}"><strong>${percentText(item.threshold)}</strong><span>${safeNumber(item.false_blocks).toLocaleString()}</span><span>${safeNumber(item.attacks_not_blocked).toLocaleString()}</span></div>`).join("")}`
            : '<p class="family-empty">No threshold comparison is available.</p>';

        const qualityScope = document.querySelector(".quality-scope p");
        if (qualityScope) {
            qualityScope.textContent = `${report.evaluation_method || "Offline held-out evaluation."} This is separate from live traffic results.`;
        }
        state.textContent = "Report matches the currently installed model.";
        state.classList.remove("quality-error");
        content.hidden = false;
    } catch (error) {
        modelQualityLoaded = false;
        state.classList.add("quality-error");
        state.textContent = error.message;
    }
}

async function loadRecoverySettings() {
    const input = document.getElementById("recoveryDuration");
    const message = document.getElementById("recoverySettingsMessage");
    if (!input) return;
    try {
        const response = await fetch(`${API_URL}/api/recovery-settings`, { cache: "no-store" });
        if (!response.ok) throw new Error("Could not load the saved observation time.");
        const data = await response.json();
        input.value = data.duration_seconds;
        input.min = data.minimum_seconds ?? 10;
        input.max = data.maximum_seconds ?? 3600;
        if (message) message.textContent = `Current setting: ${data.duration_seconds} seconds. Applies to new blocks.`;
    } catch (error) {
        if (message) message.textContent = error.message;
    }
}

function setupRecoverySettings() {
    const form = document.getElementById("recoverySettingsForm");
    const input = document.getElementById("recoveryDuration");
    const message = document.getElementById("recoverySettingsMessage");
    if (!form || !input) return;
    loadRecoverySettings();
    form.addEventListener("submit", async event => {
        event.preventDefault();
        const duration = Number(input.value);
        if (!Number.isInteger(duration) || duration < 10 || duration > 3600) {
            if (message) message.textContent = "Enter a whole number from 10 to 3600 seconds.";
            return;
        }
        const button = form.querySelector("button[type='submit']");
        if (button) button.disabled = true;
        if (message) message.textContent = "Saving observation time…";
        try {
            const response = await fetch(`${API_URL}/api/recovery-settings`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ duration_seconds: duration })
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.detail || "Could not save the observation time.");
            if (message) message.textContent = `${duration} seconds saved. This applies to new blocks.`;
        } catch (error) {
            if (message) message.textContent = error.message;
        } finally {
            if (button) button.disabled = false;
        }
    });
}

function setupDesktopNotifications() {
    const button = document.getElementById("notificationToggle");
    const status = document.getElementById("notificationStatus");
    if (!button) return;
    const supported = "Notification" in window;
    const enabled = localStorage.getItem("sentinelai.notifications") === "enabled";
    button.textContent = enabled ? "Notifications on" : "Enable desktop notifications";
    button.disabled = !supported || (supported && Notification.permission === "denied");
    if (status && !supported) status.textContent = "This browser does not support desktop notifications.";
    else if (status && Notification.permission === "denied") status.textContent = "Notifications are blocked in browser settings.";

    button.addEventListener("click", async () => {
        if (!("Notification" in window)) return;
        let permission = Notification.permission;
        if (permission === "default") permission = await Notification.requestPermission();
        if (permission !== "granted") {
            localStorage.removeItem("sentinelai.notifications");
            button.textContent = "Enable desktop notifications";
            if (status) status.textContent = "Allow notifications in the browser prompt to enable alerts.";
            return;
        }

        const willEnable = localStorage.getItem("sentinelai.notifications") !== "enabled";
        if (willEnable) {
            localStorage.setItem("sentinelai.notifications", "enabled");
            baselineNotificationRecords = new Set(latestPredictions.map(notificationRecordKey));
            button.textContent = "Notifications on";
            if (status) status.textContent = "You’ll be notified about new possible threats while this dashboard is open.";
        } else {
            localStorage.removeItem("sentinelai.notifications");
            button.textContent = "Enable desktop notifications";
            if (status) status.textContent = "Desktop notifications are off.";
        }
    });
}

function notificationRecordKey(item) {
    return String(item.record_id || `${item.timestamp}|${item.source_ip}|${item.destination_ip}`);
}

function checkForNewThreats(predictions) {
    const rows = Array.isArray(predictions) ? predictions : [];
    const keys = new Set(rows.map(notificationRecordKey));
    if (baselineNotificationRecords === null) {
        baselineNotificationRecords = keys;
        return;
    }
    if (
        localStorage.getItem("sentinelai.notifications") === "enabled" &&
        "Notification" in window && Notification.permission === "granted"
    ) {
        rows.filter(row =>
            getPrediction(row) === "ATTACK" &&
            !baselineNotificationRecords.has(notificationRecordKey(row))
        ).forEach(row => {
            const notification = new Notification("SentinelAI: possible threat", {
                body: `A possible threat was detected from ${row.source_ip || "an unknown source"}. Open Alerts to review the explanation and firewall result.`,
                tag: `sentinelai-${notificationRecordKey(row)}`
            });
            notification.onclick = () => {
                window.focus();
                showView("alerts");
                notification.close();
            };
        });
    }
    baselineNotificationRecords = keys;
}

/* =========================================================
   DASHBOARD REFRESH
========================================================= */

async function loadDashboard() {
    await Promise.all([
        loadStats(),
        loadHealth(),
        loadPredictions(),
        loadFlows()
    ]);
}

function showView(viewName, updateHistory = true) {
    const views = Array.from(document.querySelectorAll(".page-view[data-view]"));
    const target = views.find(view => view.dataset.view === viewName) ||
        views.find(view => view.dataset.view === "overview");
    if (!target) return;

    activeView = target.dataset.view;
    views.forEach(view => {
        const isActive = view === target;
        view.hidden = !isActive;
        view.classList.toggle("active-view", isActive);
    });

    const navLinks = document.querySelectorAll("[data-view-link]");
    navLinks.forEach(link => {
        const isActive = link.dataset.viewLink === activeView;
        link.classList.toggle("active", isActive && link.classList.contains("nav-item"));
        if (link.classList.contains("nav-item")) {
            if (isActive) link.setAttribute("aria-current", "page");
            else link.removeAttribute("aria-current");
        }
    });

    const titles = {
        overview: ["Overview", "Network overview", "Your current traffic and protection status, all in one place."],
        explainability: ["Explainable AI", "Understand this traffic decision", "See what the model noticed and how the firewall responded."],
        analytics: ["Analytics", "Traffic analytics", "Review traffic classifications and threat estimates over time."],
        "model-quality": ["Model quality", "Model quality report", "Review offline results from the held-out labeled test set."],
        activity: ["Live traffic", "Live network connections", "Search and review recent connections seen by packet capture."],
        alerts: ["Alerts", "Recent security alerts", "Review possible threats and their enforcement results."],
        adaptation: ["Self-healing", "Self-healing and block recovery", "Set the quiet period and review when firewall blocks are removed."],
        protection: ["Protection", "Protection status and setup", "Check capture health and the active model/firewall configuration."]
    };
    const [breadcrumb, title, subtitle] = titles[activeView];
    document.getElementById("breadcrumbCurrent").textContent = breadcrumb;
    document.getElementById("pageTitle").textContent = title;
    document.getElementById("pageSubtitle").textContent = subtitle;
    document.title = `SentinelAI | ${breadcrumb}`;

    if (updateHistory && location.hash !== `#${activeView}`) {
        history.pushState({ view: activeView }, "", `#${activeView}`);
    }
    if (activeView === "model-quality" && !modelQualityLoaded) loadModelQuality();
}

function setupSectionNavigation() {
    document.querySelectorAll("[data-view-link]").forEach(link => {
        link.addEventListener("click", event => {
            event.preventDefault();
            showView(link.dataset.viewLink);
            window.scrollTo({ top: 0, behavior: "smooth" });
        });
    });

    window.addEventListener("popstate", () => {
        showView(location.hash.slice(1) || "overview", false);
    });

    const initialView = location.hash.slice(1) || "overview";
    showView(initialView, false);

    document.getElementById("flowSearch")?.addEventListener("input", () =>
        updateFlowTable(latestFlows)
    );
    document.getElementById("flowFilter")?.addEventListener("change", () =>
        updateFlowTable(latestFlows)
    );
    document.getElementById("alertSearch")?.addEventListener("input", () =>
        updateAlerts(latestPredictions.filter(item => getPrediction(item) === "ATTACK"))
    );
    document.getElementById("alertFilter")?.addEventListener("change", () =>
        updateAlerts(latestPredictions.filter(item => getPrediction(item) === "ATTACK"))
    );
    document.getElementById("exportAlerts")?.addEventListener("click", exportAlertHistory);
    document.getElementById("refreshModelQuality")?.addEventListener("click", () => loadModelQuality(true));
    setupRecoverySettings();
    document.getElementById("recentAlerts")?.addEventListener("click", event => {
        const button = event.target.closest(".feedback-button");
        if (button) submitAlertFeedback(button);
    });
    loadAlertFeedback();
    setupDesktopNotifications();
}

setupSectionNavigation();
loadDashboard();
setInterval(loadDashboard, 5000);
setInterval(updateRecoveryCountdowns, 1000);
