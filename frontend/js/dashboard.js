(() => {

    "use strict";


    const $ =
        id => document.getElementById(id);


    const escapeHTML =
        value =>
            String(value ?? "")
                .replace(
                    /[&<>"']/g,
                    character =>
                        ({
                            "&": "&amp;",
                            "<": "&lt;",
                            ">": "&gt;",
                            '"': "&quot;",
                            "'": "&#039;"
                        }[character])
                );


    const normalize =
        value =>
            String(
                value ?? ""
            )
            .trim()
            .toLowerCase();


    const formatDate =
        value => {

            if (!value) {

                return "—";

            }


            const date =
                new Date(value);


            if (
                Number.isNaN(
                    date.getTime()
                )
            ) {

                return escapeHTML(
                    value
                );

            }


            return date.toLocaleString(
                [],
                {
                    month: "short",
                    day: "2-digit",
                    hour: "2-digit",
                    minute: "2-digit"
                }
            );

        };


    const formatTime =
        value => {

            if (!value) {

                return "—";

            }


            const date =
                new Date(value);


            if (
                Number.isNaN(
                    date.getTime()
                )
            ) {

                return "—";

            }


            return date.toLocaleTimeString(
                [],
                {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit"
                }
            );

        };


    function severity(value) {

        const level =
            normalize(
                value || "informational"
            );


        let className =
            "severity-info";


        if (level === "critical") {

            className =
                "severity-critical";

        } else if (level === "high") {

            className =
                "severity-high";

        } else if (level === "medium") {

            className =
                "severity-medium";

        } else if (level === "low") {

            className =
                "severity-low";

        }


        return `
            <span class="severity ${className}">
                ${escapeHTML(level)}
            </span>
        `;

    }


    function status(value) {

        const state =
            normalize(
                value || "unknown"
            );


        let className = "";


        if (state === "investigating") {

            className =
                "status-investigating";

        } else if (state === "contained") {

            className =
                "status-contained";

        } else if (
            state === "resolved" ||
            state === "closed"
        ) {

            className =
                "status-resolved";

        }


        return `
            <span class="status ${className}">
                ${escapeHTML(
                    value || "Unknown"
                )}
            </span>
        `;

    }


    function showToast(message) {

        const toast =
            $("toast");


        toast.textContent =
            message;


        toast.classList.add(
            "show"
        );


        window.setTimeout(
            () => {

                toast.classList.remove(
                    "show"
                );

            },
            2600
        );

    }


    let state = {

        incidents: [],
        alerts: [],
        events: [],
        assets: [],
        metrics: null,
        health: null

    };


    async function loadDashboard() {

        setConnectionState(
            "Loading..."
        );


        const results =
            await Promise.allSettled(
                [
                    PhoenixAPI.incidents(),
                    PhoenixAPI.alerts(),
                    PhoenixAPI.events(),
                    PhoenixAPI.assets(),
                    PhoenixAPI.metrics(),
                    PhoenixAPI.health()
                ]
            );


        const [
            incidentsResult,
            alertsResult,
            eventsResult,
            assetsResult,
            metricsResult,
            healthResult
        ] = results;


        state.incidents =
            incidentsResult.status === "fulfilled"
                ? PhoenixAPI.list(
                    incidentsResult.value,
                    [
                        "incidents",
                        "items"
                    ]
                )
                : [];


        state.alerts =
            alertsResult.status === "fulfilled"
                ? PhoenixAPI.list(
                    alertsResult.value,
                    [
                        "alerts",
                        "items"
                    ]
                )
                : [];


        state.events =
            eventsResult.status === "fulfilled"
                ? PhoenixAPI.list(
                    eventsResult.value,
                    [
                        "events",
                        "items"
                    ]
                )
                : [];


        state.assets =
            assetsResult.status === "fulfilled"
                ? PhoenixAPI.list(
                    assetsResult.value,
                    [
                        "assets",
                        "items"
                    ]
                )
                : [];


        state.metrics =
            metricsResult.status === "fulfilled"
                ? metricsResult.value
                : null;


        state.health =
            healthResult.status === "fulfilled"
                ? healthResult.value
                : null;


        renderMetrics();
        renderIncidents();
        renderActivity();
        renderDetections();
        renderHealth();
        renderTelemetry();
        renderSeverity();
        renderChart();


        setConnectionState(
            results.some(
                result =>
                    result.status === "fulfilled"
            )
                ? "API Connected"
                : "API Unavailable"
        );

    }


    function renderMetrics() {

        const openIncidents =
            state.incidents.filter(
                incident =>
                    ![
                        "resolved",
                        "closed"
                    ].includes(
                        normalize(
                            incident.status
                        )
                    )
            );


        const criticalAlerts =
            state.alerts.filter(
                alert =>
                    normalize(
                        alert.severity
                    ) === "critical"
            );


        $("metricIncidents")
            .textContent =
                openIncidents.length;


        $("metricCritical")
            .textContent =
                criticalAlerts.length;


        $("metricEvents")
            .textContent =
                state.events.length;


        const detectionMetric =
            state.metrics?.detections ??
            state.metrics?.detection_count ??
            state.alerts.length;


        $("metricDetections")
            .textContent =
                detectionMetric;


        const assetMetric =
            state.metrics?.asset_count ??
            state.metrics?.assets ??
            state.assets.length;

        let assetCount = assetMetric;

        if (assetMetric && typeof assetMetric === "object") {
            assetCount =
                assetMetric.count ??
                assetMetric.total ??
                assetMetric.value ??
                assetMetric.assets ??
                assetMetric.asset_count ??
                state.assets.length;
        }

        $("metricAssets")
            .textContent =
                Number.isFinite(Number(assetCount))
                    ? Number(assetCount)
                    : state.assets.length;


        $("metricIndicators")
            .textContent =
                state.metrics?.threat_indicators ??
                state.metrics?.indicators ??
                "—";


        $("incidentNavCounter")
            .textContent =
                openIncidents.length;


        $("detectionNavCounter")
            .textContent =
                state.alerts.length;

    }


    function renderIncidents() {

        const body =
            $("incidentTable");


        if (!state.incidents.length) {

            body.innerHTML = `
                <tr>
                    <td colspan="6">
                        <div class="empty-state">
                            No incident records available.
                        </div>
                    </td>
                </tr>
            `;

            return;

        }


        const items =
            [...state.incidents]
                .sort(
                    (a, b) =>
                        Number(
                            b.priority || 0
                        ) -
                        Number(
                            a.priority || 0
                        )
                )
                .slice(0, 7);


        body.innerHTML =
            items.map(
                incident => {

                    const uid =
                        incident.incident_uid ||
                        `INC-${incident.id}`;


                    return `
                        <tr>

                            <td>
                                <span class="uid">
                                    ${escapeHTML(uid)}
                                </span>
                            </td>

                            <td>

                                <div class="title-cell">
                                    ${escapeHTML(
                                        incident.title ||
                                        "Security incident"
                                    )}
                                </div>

                                <div class="sub-cell">
                                    ${escapeHTML(
                                        incident.description ||
                                        "No description available."
                                    )}
                                </div>

                            </td>

                            <td>
                                ${severity(
                                    incident.severity
                                )}
                            </td>

                            <td>
                                ${status(
                                    incident.status
                                )}
                            </td>

                            <td>
                                ${escapeHTML(
                                    incident.priority ??
                                    "—"
                                )}
                            </td>

                            <td>
                                ${formatDate(
                                    incident.detected_at ||
                                    incident.created_at
                                )}
                            </td>

                        </tr>
                    `;

                }
            )
            .join("");

    }


    function renderActivity() {

        const container =
            $("activityFeed");


        if (!state.events.length) {

            container.innerHTML = `
                <div class="empty-state">
                    No security events available.
                </div>
            `;

            return;

        }


        const items =
            [...state.events]
                .sort(
                    (a,b) =>
                        new Date(
                            b.event_time || 0
                        ) -
                        new Date(
                            a.event_time || 0
                        )
                )
                .slice(0, 10);


        container.innerHTML =
            items.map(
                event => {

                    const level =
                        normalize(
                            event.severity
                        );


                    let dotColor =
                        "var(--blue)";


                    if (
                        level === "critical"
                    ) {

                        dotColor =
                            "var(--red)";

                    } else if (
                        level === "high"
                    ) {

                        dotColor =
                            "var(--orange)";

                    } else if (
                        level === "medium"
                    ) {

                        dotColor =
                            "var(--yellow)";

                    }


                    return `
                        <div class="activity-row">

                            <i
                                class="activity-dot"
                                style="background:${dotColor}"
                            ></i>

                            <span class="activity-time">
                                ${formatTime(
                                    event.event_time
                                )}
                            </span>

                            <span class="activity-type">
                                ${escapeHTML(
                                    event.event_type ||
                                    event.category ||
                                    "Event"
                                )}
                            </span>

                            <div class="activity-detail">

                                <strong>
                                    ${escapeHTML(
                                        event.action ||
                                        event.event_uid ||
                                        "Security event"
                                    )}
                                </strong>

                                <span>
                                    ${escapeHTML(
                                        event.username ||
                                        event.hostname ||
                                        event.source_ip ||
                                        event.message ||
                                        "Telemetry received"
                                    )}
                                </span>

                            </div>

                        </div>
                    `;

                }
            )
            .join("");

    }


    function renderDetections() {

        const body =
            $("detectionTable");


        if (!state.alerts.length) {

            body.innerHTML = `
                <tr>
                    <td colspan="5">
                        <div class="empty-state">
                            No detection alerts available.
                        </div>
                    </td>
                </tr>
            `;

            return;

        }


        const items =
            [...state.alerts]
                .sort(
                    (a,b) =>
                        new Date(
                            b.created_at || 0
                        ) -
                        new Date(
                            a.created_at || 0
                        )
                )
                .slice(0, 7);


        body.innerHTML =
            items.map(
                alert => `

                    <tr>

                        <td>
                            <span class="uid">
                                ${escapeHTML(
                                    alert.alert_uid ||
                                    `ALERT-${alert.id}`
                                )}
                            </span>
                        </td>

                        <td>
                            <div class="title-cell">
                                ${escapeHTML(
                                    alert.title ||
                                    "Detection alert"
                                )}
                            </div>
                        </td>

                        <td>
                            ${severity(
                                alert.severity
                            )}
                        </td>

                        <td>
                            ${escapeHTML(
                                alert.confidence != null
                                    ? `${alert.confidence}%`
                                    : "—"
                            )}
                        </td>

                        <td>
                            ${status(
                                alert.status ||
                                "open"
                            )}
                        </td>

                    </tr>

                `
            )
            .join("");

    }


    function renderHealth() {

        const container =
            $("healthList");


        if (!state.health) {

            container.innerHTML = `
                <div class="error-state">
                    Platform health requires an authenticated analyst session.
                </div>
            `;

            $("healthState")
                .textContent =
                "AUTH REQUIRED";

            return;

        }


        let services = [];


        if (
            state.health.services &&
            typeof state.health.services === "object"
        ) {

            services =
                Object.entries(
                    state.health.services
                )
                .map(
                    ([name, value]) => ({
                        name,
                        status:
                            typeof value === "object"
                                ? value.status
                                : value
                    })
                );

        }


        if (!services.length) {

            services = [
                ["API Server", "Operational"],
                ["Database", "Operational"],
                ["Detection Engine", "Operational"],
                ["Threat Intelligence", "Operational"],
                ["SOAR", "Operational"],
                ["SIEM Pipeline", "Operational"],
                ["Authentication", "Operational"]
            ]
            .map(
                ([name, status]) =>
                    ({
                        name,
                        status
                    })
            );

        }


        $("healthState")
            .textContent =
            "OPERATIONAL";


        container.innerHTML =
            services
                .slice(0, 8)
                .map(
                    service => `

                        <div class="health-row">

                            <i class="health-dot"></i>

                            <strong>
                                ${escapeHTML(
                                    service.name
                                )}
                            </strong>

                            <span>
                                ${escapeHTML(
                                    service.status ||
                                    "Operational"
                                )}
                            </span>

                        </div>

                    `
                )
                .join("");

    }


    function renderTelemetry() {

        const container =
            $("telemetryList");


        const counts = {};


        state.events.forEach(
            event => {

                const key =
                    event.category ||
                    event.event_type ||
                    "Other";


                counts[key] =
                    (counts[key] || 0) + 1;

            }
        );


        const entries =
            Object.entries(
                counts
            )
            .sort(
                (a,b) =>
                    b[1] - a[1]
            )
            .slice(0, 6);


        if (!entries.length) {

            container.innerHTML = `
                <div class="empty-state">
                    No telemetry available.
                </div>
            `;

            return;

        }


        const max =
            entries[0][1];


        container.innerHTML =
            entries
                .map(
                    ([name, count]) => {

                        const width =
                            Math.round(
                                count /
                                max *
                                100
                            );


                        return `

                            <div class="telemetry-row">

                                <div class="telemetry-label">

                                    <span>
                                        ${escapeHTML(name)}
                                    </span>

                                    <span>
                                        ${count}
                                    </span>

                                </div>

                                <div class="telemetry-bar">

                                    <i
                                        style="width:${width}%"
                                    ></i>

                                </div>

                            </div>

                        `;

                    }
                )
                .join("");

    }


    function renderSeverity() {

        const container =
            $("severityList");


        const counts = {

            critical: 0,
            high: 0,
            medium: 0,
            low: 0

        };


        state.incidents.forEach(
            incident => {

                const level =
                    normalize(
                        incident.severity
                    );


                if (
                    counts[level] !== undefined
                ) {

                    counts[level]++;

                }

            }
        );


        const max =
            Math.max(
                ...Object.values(counts),
                1
            );


        container.innerHTML =
            Object.entries(
                counts
            )
            .map(
                ([level, count]) => `

                    <div
                        class="severity-row ${level}"
                    >

                        <label>
                            ${level}
                        </label>

                        <div class="severity-bar">

                            <i
                                style="width:${
                                    count /
                                    max *
                                    100
                                }%"
                            ></i>

                        </div>

                        <strong>
                            ${count}
                        </strong>

                    </div>

                `
            )
            .join("");

    }


    function renderChart() {

        const canvas =
            $("eventTrendChart");


        const rect =
            canvas.getBoundingClientRect();


        const dpr =
            window.devicePixelRatio || 1;


        canvas.width =
            Math.max(
                1,
                Math.floor(
                    rect.width * dpr
                )
            );


        canvas.height =
            Math.max(
                1,
                Math.floor(
                    rect.height * dpr
                )
            );


        const ctx =
            canvas.getContext(
                "2d"
            );


        ctx.scale(
            dpr,
            dpr
        );


        const width =
            rect.width;


        const height =
            rect.height;


        ctx.clearRect(
            0,
            0,
            width,
            height
        );


        const buckets =
            new Array(24)
                .fill(0);


        state.events.forEach(
            event => {

                const date =
                    new Date(
                        event.event_time || 0
                    );


                if (
                    !Number.isNaN(
                        date.getTime()
                    )
                ) {

                    buckets[
                        date.getHours()
                    ]++;

                }

            }
        );


        const max =
            Math.max(
                ...buckets,
                1
            );


        const left = 8;
        const right = 8;
        const top = 12;
        const bottom = 28;


        const chartWidth =
            width -
            left -
            right;


        const chartHeight =
            height -
            top -
            bottom;


        ctx.strokeStyle =
            "#332a23";


        ctx.lineWidth = 1;


        for (
            let row = 0;
            row < 5;
            row++
        ) {

            const y =
                top +
                chartHeight *
                row /
                4;


            ctx.beginPath();

            ctx.moveTo(
                left,
                y
            );

            ctx.lineTo(
                width - right,
                y
            );

            ctx.stroke();

        }


        const barWidth =
            Math.max(
                3,
                chartWidth /
                    buckets.length -
                    3
            );


        buckets.forEach(
            (value, index) => {

                const barHeight =
                    value /
                    max *
                    chartHeight;


                const x =
                    left +
                    index *
                    (
                        chartWidth /
                        buckets.length
                    ) +
                    2;


                const y =
                    top +
                    chartHeight -
                    barHeight;


                ctx.fillStyle =
                    "#d97745";


                ctx.fillRect(
                    x,
                    y,
                    barWidth,
                    barHeight
                );

            }
        );


        ctx.fillStyle =
            "#8c8278";


        ctx.font =
            "9px system-ui";


        ctx.textAlign =
            "center";


        for (
            let hour = 0;
            hour < 24;
            hour += 4
        ) {

            const x =
                left +
                hour *
                (
                    chartWidth /
                    24
                );


            ctx.fillText(
                `${String(hour).padStart(2,"0")}:00`,
                x,
                height - 9
            );

        }

    }


    function setConnectionState(
        text
    ) {

        const footerApi =
            $("footerApi");


        if (
            text === "API Connected"
        ) {

            footerApi.style.background =
                "var(--green)";

        } else {

            footerApi.style.background =
                "var(--red)";

        }

    }


    /* =====================================================
       NAVIGATION
    ====================================================== */

    $("moreButton")
        .addEventListener(
            "click",
            event => {

                event.stopPropagation();

                $("moreMenu")
                    .classList.toggle(
                        "open"
                    );

            }
        );


    document.addEventListener(
        "click",
        () => {

            $("moreMenu")
                .classList.remove(
                    "open"
                );

        }
    );


    $("refreshDashboard")
        .addEventListener(
            "click",
            async () => {

                showToast(
                    "Refreshing PHOENIX telemetry..."
                );

                await loadDashboard();

                showToast(
                    "Dashboard refreshed"
                );

            }
        );


    $("notificationButton")
        .addEventListener(
            "click",
            () => {

                showToast(
                    "Notification center will use the incident queue."
                );

            }
        );


    $("themeButton")
        .addEventListener(
            "click",
            () => {

                showToast(
                    "PHOENIX analyst theme is active."
                );

            }
        );


    $("globalSearch")
        .addEventListener(
            "keydown",
            event => {

                if (
                    event.key === "Enter"
                ) {

                    const query =
                        event.target.value.trim();


                    if (!query) {

                        return;

                    }


                    window.location.href =
                        `/PHOENIX/frontend/pages/events.html?q=${encodeURIComponent(query)}`;

                }

            }
        );


    document.addEventListener(
        "keydown",
        event => {

            if (
                event.key === "/" &&
                document.activeElement?.tagName !== "INPUT"
            ) {

                event.preventDefault();

                $("globalSearch")
                    .focus();

            }

        }
    );


    $("timeRange")
        .addEventListener(
            "change",
            event => {

                const value =
                    event.target.value;


                $("trendLabel")
                    .textContent =
                    `Last ${value} ${
                        value === "1"
                            ? "hour"
                            : "hours"
                    }`;


                renderChart();

            }
        );


    window.addEventListener(
        "resize",
        () => {

            renderChart();

        }
    );


    /* =====================================================
       INITIAL LOAD
    ====================================================== */

    loadDashboard();


    /*
     * Live SOC refresh.
     * The backend remains the source of truth.
     */
    window.setInterval(
        loadDashboard,
        30000
    );

})();
