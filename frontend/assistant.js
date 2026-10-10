const assistantToggle = document.getElementById('assistantToggle');
const assistantPanel = document.getElementById('assistantPanel');
const assistantClose = document.getElementById('assistantClose');
const assistantForm = document.getElementById('assistantForm');
const assistantInput = document.getElementById('assistantInput');
const assistantMessages = document.getElementById('assistantMessages');
const assistantStatus = document.getElementById('assistantStatus');
const apiBase = (window.EVOLVA_API_BASE || '').replace(/\/$/, '');

function setAssistantOpen(open) {
    assistantPanel.hidden = !open;
    assistantToggle.setAttribute('aria-expanded', String(open));
    if (open) assistantInput.focus();
}

assistantToggle.addEventListener('click', () => setAssistantOpen(assistantPanel.hidden));
assistantClose.addEventListener('click', () => setAssistantOpen(false));

function addMessage(text, role) {
    const message = document.createElement('p');
    message.className = `assistant-message ${role === 'user' ? 'assistant-user' : 'assistant-reply'}`;
    message.textContent = text;
    assistantMessages.append(message);
    assistantMessages.scrollTop = assistantMessages.scrollHeight;
}

assistantForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const message = assistantInput.value.trim();
    if (!message) return;
    addMessage(message, 'user');
    assistantInput.value = '';
    assistantInput.disabled = true;
    assistantForm.querySelector('button').disabled = true;
    assistantStatus.textContent = 'Evol está pensando…';
    try {
        const response = await fetch(`${apiBase}/api/assistant`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
        });
        const result = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(result.error || 'No se pudo obtener una respuesta.');
        addMessage(result.answer, 'assistant');
        assistantStatus.textContent = 'Las respuestas son orientación inicial para tu negocio.';
    } catch (error) {
        addMessage(error.message, 'assistant');
        assistantStatus.textContent = 'Puedes volver a intentarlo en cualquier momento.';
    } finally {
        assistantInput.disabled = false;
        assistantForm.querySelector('button').disabled = false;
        assistantInput.focus();
    }
});
