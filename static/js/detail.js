
document.addEventListener("DOMContentLoaded", function () {
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    const tooltipList = [...tooltipTriggerList].map(el => new bootstrap.Tooltip(el));
});

document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("pre[id^='postdata-'], pre[id^='response-']").forEach(function(pre) {
        let raw = pre.textContent.trim();

        raw = raw.replace(/\\"/g, '"');

        if (!(raw.startsWith("{") || raw.startsWith("["))) {
            return;
        }

        try {
            const obj = JSON.parse(raw);
            pre.textContent = JSON.stringify(obj, null, 2);
        } catch (e) {
            console.warn("Não foi possível formatar JSON:", e, raw);
        }
    });
});

document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-bs-toggle='collapse']").forEach(function (header) {
        const target = document.querySelector(header.dataset.bsTarget);
        const card = header.closest(".card");

        target.addEventListener("show.bs.collapse", () => {
            card.classList.add("expanded");
        });

        target.addEventListener("hide.bs.collapse", () => {
            card.classList.remove("expanded");
        });
    });
});