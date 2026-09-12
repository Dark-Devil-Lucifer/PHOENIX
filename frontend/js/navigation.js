document.addEventListener("DOMContentLoaded", () => {

    /* =====================================================
       PHOENIX GLOBAL NAVIGATION
       ===================================================== */

    const moreButton =
        document.getElementById("moreButton") ||
        document.getElementById("more-navigation");

    const moreMenu =
        document.getElementById("moreMenu") ||
        document.getElementById("more-menu");

    if (moreButton && moreMenu) {

        const closeMoreMenu = () => {
            moreMenu.classList.add("hidden");
            moreButton.setAttribute("aria-expanded", "false");
        };

        const openMoreMenu = () => {
            moreMenu.classList.remove("hidden");
            moreButton.setAttribute("aria-expanded", "true");
        };

        moreButton.setAttribute("aria-haspopup", "true");
        moreButton.setAttribute("aria-expanded", "false");

        moreButton.addEventListener("click", event => {
            event.preventDefault();
            event.stopPropagation();

            const isOpen =
                !moreMenu.classList.contains("hidden");

            if (isOpen) {
                closeMoreMenu();
            } else {
                openMoreMenu();
            }
        });

        document.addEventListener("click", event => {

            if (
                !moreMenu.contains(event.target) &&
                !moreButton.contains(event.target)
            ) {
                closeMoreMenu();
            }

        });

        document.addEventListener("keydown", event => {

            if (event.key === "Escape") {
                closeMoreMenu();
            }

        });

        /* Keep dropdown clicks from closing themselves */
        moreMenu.addEventListener("click", event => {
            event.stopPropagation();
        });

        /* Close after navigating */
        moreMenu.querySelectorAll("a").forEach(link => {
            link.addEventListener("click", () => {
                closeMoreMenu();
            });
        });
    }


    /* =====================================================
       GLOBAL SEARCH
       ===================================================== */

    const search =
        document.getElementById("globalSearch") ||
        document.getElementById("global-search");

    document.addEventListener("keydown", event => {

        if (
            event.key === "/" &&
            document.activeElement !== search &&
            document.activeElement?.tagName !== "INPUT" &&
            document.activeElement?.tagName !== "TEXTAREA" &&
            document.activeElement?.tagName !== "SELECT"
        ) {
            event.preventDefault();
            search?.focus();
        }

        if (
            event.key === "Escape" &&
            search
        ) {
            search.blur();
        }

    });

    search?.addEventListener("keydown", event => {

        if (event.key === "Enter") {

            const query =
                search.value.trim();

            if (query) {

                console.log(
                    "PHOENIX global search:",
                    query
                );

                window.dispatchEvent(
                    new CustomEvent(
                        "phoenix-search",
                        {
                            detail: {
                                query
                            }
                        }
                    )
                );
            }
        }

    });

});
