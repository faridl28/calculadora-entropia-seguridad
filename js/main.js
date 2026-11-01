'use strict';

document.addEventListener('DOMContentLoaded', () => {
    // Referencias del DOM - Módulo de Análisis
    const btnAnalyze = document.getElementById('btn-analyze');
    const inputPassword = document.getElementById('password-input');
    const spanEntropyResult = document.getElementById('entropy-result');
    const spanSecurityLevel = document.getElementById('security-level');

    // Referencias del DOM - Módulo de Generación
    const btnGenerate = document.getElementById('btn-generate');
    const selectTheme = document.getElementById('theme-select');
    const spanGeneratedPassword = document.getElementById('generated-password');
    const spanGeneratedEntropy = document.getElementById('generated-entropy');

    // 1. Evento: Analizar entropía de la entrada del usuario
    btnAnalyze.addEventListener('click', () => {
        const password = inputPassword.value.trim();

        if (!password) {
            alert('Input requerido: Ingresa una contraseña para analizar.');
            return;
        }

        // Consumo de la función expuesta globalmente por entropy.js
        const result = window.calculateEntropy(password);

        spanEntropyResult.textContent = result.entropy;
        spanSecurityLevel.textContent = result.classification;

        // Inyección de estilos dinámicos (Feedback visual)
        switch (result.classification) {
            case 'Débil':
                spanSecurityLevel.style.color = '#dc3545'; // Rojo
                break;
            case 'Fuerte':
                spanSecurityLevel.style.color = '#fd7e14'; // Naranja
                break;
            case 'Segura':
                spanSecurityLevel.style.color = '#198754'; // Verde
                break;
            default:
                spanSecurityLevel.style.color = 'inherit';
        }
    });

    // 2. Evento: Generar passphrase temática basada en Diceware
    btnGenerate.addEventListener('click', () => {
        const selectedTheme = selectTheme.value; // 'english', 'spanish', 'cooking', 'motorcycles'

        try {
            // Consumo del generador criptográfico expuesto por entropy.js
            const result = window.generatePassphrase(selectedTheme);

            spanGeneratedPassword.textContent = result.password;
            spanGeneratedEntropy.textContent = result.entropy;
        } catch (error) {
            console.error('[Error de Generación]', error);
            alert('Ocurrió un error al generar la contraseña. Revisa la consola para más detalles.');
        }
    });
});