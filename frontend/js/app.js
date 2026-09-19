document.addEventListener("DOMContentLoaded", () => {
    loadOperations();

    document
        .getElementById("refresh-button")
        ?.addEventListener("click", loadOperations);

    document
        .getElementById("operations-refresh")
        ?.addEventListener("click", loadOperations);

    document
        .getElementById("open-incidents")
        ?.addEventListener("click", () => {
            window.location.href = "/PHOENIX/frontend/pages/incidents.html";
        });

    document
        .getElementById("view-all-incidents")
        ?.addEventListener("click", () => {
            window.location.href = "/PHOENIX/frontend/pages/incidents.html";
        });

    document
        .getElementById("view-events")
        ?.addEventListener("click", () => {
            window.location.href = "/PHOENIX/frontend/pages/events.html";
        });
});


async function loadOperations() {
    const elements = [
        "metric-incidents",
        "metric-critical-alerts",
        "metric-events",
        "metric-assets",
        "metric-detections"
    ];

    elements.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = "…";
        }
    });

    try {
        const [
            metrics,
            incidents,
            alerts,
            events,
            health
        ] = await Promise.all([
            PhoenixAPI.metrics(),
            PhoenixAPI.incidents(),
            PhoenixAPI.alerts(),
            PhoenixAPI.events(),
            PhoenixAPI.health()
        ]);

        renderMetrics(
            metrics,
            incidents,
            alerts,
            events
        );

        renderIncidents(incidents);
        renderActivity(events);
        renderHealth(health);

        setConnectionStatus(true);

    } catch (error) {
        console.error("PHOENIX operations load failed:", error);

        setConnectionStatus(false);

        showOperationsError(error);
    }
}


function renderMetrics(
    metrics,
    incidents,
    alerts,
    events
) {
    const incidentItems =
        Array.isArray(incidents)
            ? incidents
            : incidents?.items || incidents?.incidents || [];

    const alertItems =
        Array.isArray(alerts)
            ? alerts
            : alerts?.items || alerts?.alerts || [];

    const eventItems =
        Array.isArray(events)
            ? events
            : events?.items || events?.events || [];

    const metricData = metrics || {};

    const assets =
        metricData.assets ??
        metricData.asset_count ??
        metricData.total_assets ??
        0;

    const detections =
        metricData.detections ??
        metricData.detection_count ??
        metricData.total_detections ??
        0;

    const criticalAlerts = alertItems.filter(
        alert =>
            String(alert.severity || "").toLowerCase() ===
            "critical"
    ).length;

    const openIncidents = incidentItems.filter(
        incident =>
            !["resolved", "closed"].includes(
                String(incident.status || "").toLowerCase()
            )
    );

    setText(
        "metric-incidents",
        openIncidents.length
    );

    setText(
        "metric-critical-alerts",
        criticalAlerts
    );

    setText(
        "metric-events",
        eventItems.length
    );

    setText(
        "metric-assets",
        assets
    );

    setText(
        "metric-detections",
        detections
    );

    setText(
        "incident-nav-count",
        openIncidents.length
    );

    renderPriority(openIncidents);
}


function renderPriority(incidents) {
    const counts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
    };

    incidents.forEach(incident => {
        const severity =
            String(incident.severity || "")
                .toLowerCase();

        if (severity in counts) {
            counts[severity]++;
        }
    });

    const maximum =
        Math.max(...Object.values(counts), 1);

    Object.entries(counts).forEach(
        ([severity, count]) => {
            setText(
                `priority-${severity}`,
                count
            );

            const bar =
                document.getElementById(
                    `${severity}-bar`
                );

            if (bar) {
                bar.style.width =
                    `${(count / maximum) * 100}%`;

                bar.style.background =
                    severity === "critical"
                        ? "var(--critical)"
                        : severity === "high"
                            ? "var(--high)"
                            : severity === "medium"
                                ? "var(--medium)"
                                : "var(--low)";
            }
        }
    );
}


function renderIncidents(data) {
    const incidents =
        Array.isArray(data)
            ? data
            : data?.items || data?.incidents || [];

    const tbody =
        document.getElementById("incident-table");

    if (!tbody) {
        return;
    }

    if (!incidents.length) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5">
                    <div class="empty-state">
                        No open incidents.
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    const active = incidents
        .filter(
            incident =>
                !["resolved", "closed"].includes(
                    String(
                        incident.status || ""
                    ).toLowerCase()
                )
        )
        .sort(
            (a, b) =>
                Number(b.priority || 0) -
                Number(a.priority || 0)
        )
        .slice(0, 8);

    tbody.innerHTML = active.map(
        incident => `
            <tr>
                <td>
                    <strong>
                        ${escapeHTML(
                            incident.incident_uid ||
                            `INC-${incident.id}`
                        )}
                    </strong>
                    <div class="muted">
                        ${escapeHTML(
                            incident.title || "Security incident"
                        )}
                    </div>
                </td>

                <td>
                    ${severityBadge(
                        incident.severity
                    )}
                </td>

                <td>
                    <strong>
                        ${escapeHTML(
                            String(
                                incident.priority ?? "—"
                            )
                        )}
                    </strong>
                </td>

                <td>
                    <span class="status-badge">
                        ${escapeHTML(
                            incident.status || "unknown"
                        )}
                    </span>
                </td>

                <td class="muted">
                    ${formatDate(
                        incident.detected_at ||
                        incident.created_at
                    )}
                </td>
            </tr>
        `
    ).join("");
}


function renderActivity(data) {
    const events =
        Array.isArray(data)
            ? data
            : data?.items || data?.events || [];

    const container =
        document.getElementById("activity-list");

    if (!container) {
        return;
    }

    if (!events.length) {
        container.innerHTML = `
            <div class="empty-state">
                No security events available.
            </div>
        `;
        return;
    }

    const latest = [...events]
        .sort(
            (a, b) =>
                new Date(
                    b.event_time ||
                    b.timestamp ||
                    b.created_at ||
                    0
                ) -
                new Date(
                    a.event_time ||
                    a.timestamp ||
                    a.created_at ||
                    0
                )
        )
        .slice(0, 8);

    container.innerHTML = latest.map(
        event => {
            const severity =
                String(
                    event.severity || "informational"
                ).toLowerCase();

            return `
                <div class="activity-item">
                    <div
                        class="activity-marker"
                        style="background: var(--${severity === "critical"
                            ? "critical"
                            : severity === "high"
                                ? "high"
                                : severity === "medium"
                                    ? "medium"
                                    : "info"})"
                    ></div>

                    <div class="activity-content">
                        <div class="activity-title">
                            ${escapeHTML(
                                event.action ||
                                event.event_type ||
                                "Security event"
                            )}
                        </div>

                        <div class="activity-meta">
                            ${escapeHTML(
                                event.username ||
                                event.hostname ||
                                event.source_ip ||
                                "Unknown source"
                            )}
                            ${event.event_uid
                                ? ` · ${escapeHTML(event.event_uid)}`
                                : ""}
                        </div>
                    </div>

                    <div class="activity-time">
                        ${formatDate(
                            event.event_time ||
                            event.timestamp ||
                            event.created_at
                        )}
                    </div>
                </div>
            `;
        }
    ).join("");
}


function renderHealth(data) {
    const container =
        document.getElementById("health-list");

    if (!container) {
        return;
    }

    if (!data) {
        container.innerHTML = `
            <div class="empty-state">
                Health data unavailable.
            </div>
        `;
        return;
    }

    let checks = [];

    if (Array.isArray(data)) {
        checks = data;
    } else if (data.services) {
        checks = Object.entries(data.services)
            .map(([name, value]) => ({
                name,
                status:
                    typeof value === "object"
                        ? value.status
                        : value
            }));
    } else {
        checks = Object.entries(data)
            .filter(
                ([key]) =>
                    typeof data[key] !== "object" ||
                    data[key] === null
            )
            .slice(0, 8)
            .map(([name, status]) => ({
                name,
                status
            }));
    }

    if (!checks.length) {
        container.innerHTML = `
            <div class="empty-state">
                Platform health available.
            </div>
        `;
        return;
    }

    container.innerHTML = checks.map(
        check => `
            <div class="activity-item">
                <div
                    class="activity-marker"
                    style="background: var(--success)"
                ></div>

                <div class="activity-content">
                    <div class="activity-title">
                        ${escapeHTML(
                            String(check.name)
                        )}
                    </div>

                    <div class="activity-meta">
                        PHOENIX platform service
                    </div>
                </div>

                <div class="activity-time">
                    ${escapeHTML(
                        String(
                            check.status ??
                            "available"
                        )
                    )}
                </div>
            </div>
        `
    ).join("");
}


function showOperationsError(error) {
    const activity =
        document.getElementById("activity-list");

    if (activity) {
        activity.innerHTML = `
            <div class="error-state">
                Unable to load live security activity.
                ${escapeHTML(
                    error?.message ||
                    "API request failed."
                )}
            </div>
        `;
    }
}


function setConnectionStatus(connected) {
    const status =
        document.querySelector(".connection-status");

    if (!status) {
        return;
    }

    status.innerHTML = connected
        ? `
            <span
                class="status-dot"
                style="background: var(--success)"
            ></span>
            <span>API Connected</span>
        `
        : `
            <span
                class="status-dot"
                style="background: var(--critical)"
            ></span>
            <span>API Unavailable</span>
        `;
}


function setText(id, value) {
    const element =
        document.getElementById(id);

    if (element) {
        element.textContent = value;
    }
}


function severityBadge(severity) {
    const normalized =
        String(
            severity || "informational"
        ).toLowerCase();

    const allowed = [
        "critical",
        "high",
        "medium",
        "low",
        "informational"
    ];

    const value =
        allowed.includes(normalized)
            ? normalized
            : "informational";

    return `
        <span class="severity severity-${value}">
            ${escapeHTML(value)}
        </span>
    `;
}


function formatDate(value) {
    if (!value) {
        return "—";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return escapeHTML(
            String(value)
        );
    }

    return date.toLocaleString(
        undefined,
        {
            month: "short",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit"
        }
    );
}


function escapeHTML(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}
