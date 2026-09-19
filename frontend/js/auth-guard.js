(() => {

"use strict";


const PUBLIC_PATHS = [
    "/PHOENIX/frontend/login.html"
];


function currentPath() {
    return window.location.pathname;
}


function isLoginPage() {
    return PUBLIC_PATHS.includes(
        currentPath()
    );
}


function hasToken() {

    return Boolean(
        localStorage.getItem(
            "phoenix_access_token"
        )
    );

}


async function verifySession() {

    if (isLoginPage()) {
        return;
    }


    if (!hasToken()) {

        window.location.href =
            "/PHOENIX/frontend/login.html";

        return;

    }


    if (
        !window.PhoenixAPI ||
        typeof PhoenixAPI.me !== "function"
    ) {
        return;
    }


    try {

        const user =
            await PhoenixAPI.me();


        const name =
            document.getElementById(
                "analystName"
            );

        const role =
            document.getElementById(
                "analystRole"
            );


        if (name) {

            name.textContent =
                user.username ||
                user.name ||
                "Analyst";

        }


        if (role) {

            const roles =
                user.roles ||
                user.role ||
                "SOC Analyst";

            role.textContent =
                Array.isArray(roles)
                    ? roles.join(", ")
                    : roles;

        }


    } catch (error) {

        console.warn(
            "PHOENIX session validation failed:",
            error
        );

        localStorage.removeItem(
            "phoenix_access_token"
        );

        window.location.href =
            "/PHOENIX/frontend/login.html";

    }

}


document.addEventListener(
    "DOMContentLoaded",
    verifySession
);

})();
