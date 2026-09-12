(() => {
    "use strict";

    /*
     * ============================================================
     * PHOENIX API CLIENT
     * Autonomous Enterprise Cyber Defense Platform
     * ============================================================
     *
     * FastAPI backend and frontend are served from the same origin.
     *
     * Example:
     *   http://127.0.0.1:8000
     *
     * The browser automatically uses the host that opened PHOENIX.
     */

    const API_BASE = window.location.origin;

    const TOKEN_KEY = "phoenix_access_token";


    /* ============================================================
       AUTH TOKEN
       ============================================================ */

    function getToken() {
        return localStorage.getItem(TOKEN_KEY);
    }


    function setToken(token) {

        if (token) {
            localStorage.setItem(
                TOKEN_KEY,
                token
            );
        }

    }


    function clearToken() {
        localStorage.removeItem(TOKEN_KEY);
    }


    function isAuthenticated() {
        return Boolean(getToken());
    }


    /* ============================================================
       ERROR NORMALIZATION
       ============================================================ */

    function getErrorMessage(data, status) {

        const fallback =
            `HTTP ${status}`;

        if (!data) {
            return fallback;
        }


        /*
         * FastAPI validation errors commonly look like:
         *
         * {
         *   "detail": [
         *      {
         *          "loc": [...],
         *          "msg": "...",
         *          "type": "..."
         *      }
         *   ]
         * }
         *
         * Do NOT allow this to become:
         *
         *     [object Object]
         */

        if (Array.isArray(data.detail)) {

            return data.detail
                .map(item => {

                    if (
                        typeof item === "string"
                    ) {
                        return item;
                    }


                    if (
                        item &&
                        typeof item.msg === "string"
                    ) {
                        return item.msg;
                    }


                    if (
                        item &&
                        typeof item.message === "string"
                    ) {
                        return item.message;
                    }


                    try {
                        return JSON.stringify(item);
                    } catch {
                        return "Request validation failed.";
                    }

                })
                .join("; ");

        }


        if (
            typeof data.detail === "string"
        ) {
            return data.detail;
        }


        if (
            typeof data.message === "string"
        ) {
            return data.message;
        }


        if (
            typeof data.error === "string"
        ) {
            return data.error;
        }


        if (
            typeof data === "string" &&
            data.trim()
        ) {
            return data;
        }


        try {

            if (
                typeof data === "object"
            ) {
                return JSON.stringify(data);
            }

        } catch {
            // Ignore JSON serialization errors.
        }


        return fallback;

    }


    /* ============================================================
       HTTP RESPONSE PARSER
       ============================================================ */

    async function parseResponse(response) {

        const contentType =
            response.headers.get(
                "content-type"
            ) || "";


        if (
            contentType.includes(
                "application/json"
            )
        ) {

            try {

                return await response.json();

            } catch {

                return null;

            }

        }


        try {

            return await response.text();

        } catch {

            return "";

        }

    }


    /* ============================================================
       HTTP REQUEST
       ============================================================ */

    async function request(
        path,
        options = {}
    ) {

        if (
            !path.startsWith("/")
        ) {
            path = `/${path}`;
        }


        const url =
            `${API_BASE}${path}`;


        const config = {

            method:
                options.method ||
                "GET",

            headers:
                buildHeaders(
                    options.headers ||
                    {}
                ),

            credentials:
                "same-origin"

        };


        /*
         * Request body handling.
         *
         * Objects are automatically serialized
         * as JSON.
         */

        if (
            options.body !== undefined
        ) {

            if (
                options.body instanceof
                FormData
            ) {

                config.body =
                    options.body;

            } else if (
                typeof options.body ===
                "object" &&
                options.body !== null
            ) {

                config.headers =
                    buildHeaders({

                        "Content-Type":
                            "application/json",

                        ...(options.headers ||
                            {})

                    });


                config.body =
                    JSON.stringify(
                        options.body
                    );

            } else {

                config.body =
                    options.body;

            }

        }


        let response;


        try {

            response =
                await fetch(
                    url,
                    config
                );

        } catch (error) {

            console.error(
                "[PHOENIX] API connection error:",
                error
            );


            throw new Error(
                `Cannot connect to PHOENIX API: ${url}`
            );

        }


        const data =
            await parseResponse(
                response
            );


        if (!response.ok) {

            if (
                response.status === 401
            ) {

                window.dispatchEvent(
                    new CustomEvent(
                        "phoenix:unauthorized"
                    )
                );

            }


            throw new Error(
                getErrorMessage(
                    data,
                    response.status
                )
            );

        }


        return data;

    }


    /* ============================================================
       HTTP HEADERS
       ============================================================ */

    function buildHeaders(
        extra = {}
    ) {

        const headers = {

            "Accept":
                "application/json",

            ...extra

        };


        const token =
            getToken();


        if (token) {

            headers[
                "Authorization"
            ] =
                `Bearer ${token}`;

        }


        return headers;

    }


    /* ============================================================
       RESPONSE NORMALIZATION
       ============================================================ */

    function list(
        data,
        keys = []
    ) {

        if (
            Array.isArray(data)
        ) {
            return data;
        }


        if (
            data &&
            Array.isArray(
                data.items
            )
        ) {
            return data.items;
        }


        for (
            const key of keys
        ) {

            if (
                data &&
                Array.isArray(
                    data[key]
                )
            ) {

                return data[key];

            }

        }


        return [];

    }


    /* ============================================================
       CORE API
       ============================================================ */

    function health() {

        return request(
            "/api/health"
        );

    }


    function assets() {

        return request(
            "/api/assets"
        );

    }


    function events() {

        return request(
            "/api/events"
        );

    }


    function alerts() {

        return request(
            "/api/alerts"
        );

    }


    function incidents() {

        return request(
            "/api/incidents"
        );

    }


    /* ============================================================
       METRICS
       ============================================================ */

    function metrics() {

        return request(
            "/api/metrics/soc"
        );

    }


    function securityHealth() {

        return request(
            "/api/metrics/health"
        );

    }


    /* ============================================================
       DETECTIONS
       ============================================================ */

    function detections() {

        return request(
            "/api/detections"
        );

    }


    function detectionRules() {

        return request(
            "/api/detection-rules"
        );

    }


    /* ============================================================
       THREAT INTELLIGENCE
       ============================================================ */

    function intelligence() {

        return request(
            "/api/intelligence"
        );

    }


    /* ============================================================
       VULNERABILITY MANAGEMENT
       ============================================================ */

    function vulnerabilities() {

        return request(
            "/api/vulnerabilities"
        );

    }


    /* ============================================================
       ZERO TRUST
       ============================================================ */

    function zeroTrustPolicies() {

        return request(
            "/api/zero-trust/policies"
        );

    }


    /* ============================================================
       ENDPOINT / EDR
       ============================================================ */

    function endpoints() {

        return request(
            "/api/endpoints"
        );

    }


    /* ============================================================
       CLOUD
       ============================================================ */

    function cloudAccounts() {

        return request(
            "/api/cloud/accounts"
        );

    }


    function cloudAssets() {

        return request(
            "/api/cloud/assets"
        );

    }


    function cloudFindings() {

        return request(
            "/api/cloud/findings"
        );

    }


    /* ============================================================
       KUBERNETES
       ============================================================ */

    function kubernetesClusters() {

        return request(
            "/api/kubernetes/clusters"
        );

    }


    function kubernetesImages() {

        return request(
            "/api/kubernetes/images"
        );

    }


    function kubernetesFindings() {

        return request(
            "/api/kubernetes/findings"
        );

    }


    function kubernetesWorkloads() {

        return request(
            "/api/kubernetes/workloads"
        );

    }


    /* ============================================================
       DLP
       ============================================================ */

    function dlpResources() {

        return request(
            "/api/dlp/resources"
        );

    }


    function dlpEvents() {

        return request(
            "/api/dlp/events"
        );

    }


    /* ============================================================
       RECOVERY
       ============================================================ */

    function recoveryBackups() {

        return request(
            "/api/recovery/backups"
        );

    }


    function recoveryTests() {

        return request(
            "/api/recovery/tests"
        );

    }


    /* ============================================================
       RISK
       ============================================================ */

    function risks() {

        return request(
            "/api/risk"
        );

    }


    /* ============================================================
       COMPLIANCE
       ============================================================ */

    function complianceControls() {

        return request(
            "/api/compliance/controls"
        );

    }


    function complianceSummary() {

        return request(
            "/api/compliance/summary"
        );

    }


    /* ============================================================
       THREAT HUNTING
       ============================================================ */

    function huntingQueries() {

        return request(
            "/api/hunting/queries"
        );

    }


    function huntingRuns() {

        return request(
            "/api/hunting/runs"
        );

    }


    /* ============================================================
       FORENSICS
       ============================================================ */

    function forensicArtifacts() {

        return request(
            "/api/forensics/artifacts"
        );

    }


    /* ============================================================
       CASES
       ============================================================ */

    function cases() {

        return request(
            "/api/cases"
        );

    }


    /* ============================================================
       REPORTS
       ============================================================ */

    function executiveReport() {

        return request(
            "/api/reports/executive"
        );

    }


    /* ============================================================
       AUTHENTICATION
       ============================================================ */

    async function login(
        username,
        password
    ) {

        /*
         * PHOENIX FastAPI expects JSON.
         *
         * DO NOT use:
         *
         * application/x-www-form-urlencoded
         *
         * here.
         */

        const response =
            await fetch(
                `${API_BASE}/api/auth/login`,
                {

                    method: "POST",

                    headers: {

                        "Content-Type":
                            "application/json",

                        "Accept":
                            "application/json"

                    },

                    credentials:
                        "same-origin",

                    body:
                        JSON.stringify({

                            username:
                                username,

                            password:
                                password

                        })

                }
            );


        const data =
            await parseResponse(
                response
            );


        if (!response.ok) {

            throw new Error(
                getErrorMessage(
                    data,
                    response.status
                )
            );

        }


        const token =
            data?.access_token ||
            data?.token;


        if (!token) {

            throw new Error(
                "Login succeeded but no access token was returned."
            );

        }


        setToken(token);


        return data;

    }


    /* ============================================================
       CURRENT USER
       ============================================================ */

    function me() {

        return request(
            "/api/auth/me"
        );

    }


    /* ============================================================
       LOGOUT
       ============================================================ */

    function logout() {

        clearToken();


        window.location.href =
            "/frontend/";

    }


    /* ============================================================
       GLOBAL PHOENIX API OBJECT
       ============================================================ */

    window.PhoenixAPI = {

        /* Base */
        baseURL:
            API_BASE,

        request,
        list,

        /* Authentication */
        login,
        me,
        logout,

        getToken,
        setToken,
        clearToken,
        isAuthenticated,

        /* Core */
        health,
        assets,
        events,
        alerts,
        incidents,

        /* Metrics */
        metrics,
        securityHealth,

        /* Detection */
        detections,
        detectionRules,

        /* Threat Intelligence */
        intelligence,

        /* Vulnerability */
        vulnerabilities,

        /* Zero Trust */
        zeroTrustPolicies,

        /* Endpoint / EDR */
        endpoints,

        /* Cloud */
        cloudAccounts,
        cloudAssets,
        cloudFindings,

        /* Kubernetes */
        kubernetesClusters,
        kubernetesImages,
        kubernetesFindings,
        kubernetesWorkloads,

        /* DLP */
        dlpResources,
        dlpEvents,

        /* Recovery */
        recoveryBackups,
        recoveryTests,

        /* Risk */
        risks,

        /* Compliance */
        complianceControls,
        complianceSummary,

        /* Threat Hunting */
        huntingQueries,
        huntingRuns,

        /* Forensics */
        forensicArtifacts,

        /* Cases */
        cases,

        /* Reports */
        executiveReport

    };


    /* ============================================================
       UNAUTHORIZED EVENT
       ============================================================ */

    window.addEventListener(
        "phoenix:unauthorized",
        () => {

            console.warn(
                "[PHOENIX] API returned HTTP 401."
            );

        }
    );


    /* ============================================================
       INITIALIZATION CHECK
       ============================================================ */

    console.info(
        `[PHOENIX] API client initialized: ${API_BASE}`
    );


    console.info(
        "[PHOENIX] PhoenixAPI available:",
        Boolean(
            window.PhoenixAPI
        )
    );


})();
