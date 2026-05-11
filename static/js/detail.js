
document.addEventListener("DOMContentLoaded", function () {
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    const tooltipList = [...tooltipTriggerList].map(el => new bootstrap.Tooltip(el));
});

document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("pre[id^='postdata-'], pre[id^='response-']").forEach(function (pre) {
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
        const card = header.closest(".card, .inspector-row");

        if (!target || !card) return;

        target.addEventListener("show.bs.collapse", () => {
            card.classList.add("expanded");
        });

        target.addEventListener("hide.bs.collapse", () => {
            card.classList.remove("expanded");
        });
    });
});

document.addEventListener('DOMContentLoaded', function () {
    // 1. Seleciona os elementos do modal
    const aiModal = document.getElementById('aiAdviceModal');
    const contentBox = document.getElementById('ai-content');
    const loadingIndicator = document.getElementById('ai-loading');

    // 2. Escuta o clique nos ícones do robô
    document.querySelectorAll('.ai-logic-trigger').forEach(trigger => {
        trigger.addEventListener('click', async function (e) {
            e.preventDefault();

            // Pega a descrição do problema que está no atributo data-problem
            const problemDescription = this.getAttribute('data-problem');

            // Reseta o modal: limpa texto antigo e mostra o carregando
            contentBox.innerText = '';
            loadingIndicator.classList.remove('d-none');

            try {
                // 3. Chama a rota do Flask
                const response = await fetch('/get-ai-advice', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ problem: problemDescription })
                });

                if (!response.ok) throw new Error('Erro na requisição');

                const data = await response.json();

                // 4. Exibe o resultado da IA
                contentBox.innerText = data.advice;
            } catch (error) {
                contentBox.innerText = "Ops! Não consegui falar com a IA. Verifique se sua chave API está correta nas Configurações.";
                console.error('Erro:', error);
            } finally {
                // Esconde o carregando
                loadingIndicator.classList.add('d-none');
            }
        });
    });
});

// Lógica para copiar para a área de transferência
document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".copy-to-clipboard").forEach(function (button) {
        button.addEventListener("click", function () {
            const targetId = this.dataset.targetId;
            const targetElement = document.getElementById(targetId);
            if (targetElement) {
                const textToCopy = targetElement.textContent.trim();
                navigator.clipboard.writeText(textToCopy).then(() => {
                    // Opcional: feedback visual para o usuário (ex: mudar ícone para check)
                    this.innerHTML = '<i class="bi bi-check-lg text-success"></i>';
                    setTimeout(() => this.innerHTML = '<i class="bi bi-clipboard"></i>', 1500);
                }).catch(err => console.error('Failed to copy text: ', err));
            }
        });
    });
});