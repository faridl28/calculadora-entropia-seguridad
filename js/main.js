'use strict';

/**
 * @fileoverview Controladores del DOM, Event Listeners y Lógica de Interfaz.
 * Cumple con principios de bajo acoplamiento y evaluación en tiempo real de entropía.
 */

document.addEventListener('DOMContentLoaded', () => {
    // ========================================================================
    // 1. REFERENCIAS DEL DOM - MÓDULO 1: ANALIZADOR DE ENTROPÍA
    // ========================================================================
    const btnAnalyze = document.getElementById('btn-analyze');
    const inputPassword = document.getElementById('password-input');
    const spanEntropyResult = document.getElementById('entropy-result');
    const spanSecurityLevel = document.getElementById('security-level');

    // ========================================================================
    // 2. REFERENCIAS DEL DOM - MÓDULO 2: GENERADOR TEMÁTICO DINÁMICO (IA)
    // ========================================================================
    const btnGenerate = document.getElementById('btn-generate');
    const inputTheme = document.getElementById('theme-input');
    const spanGeneratedPassword = document.getElementById('generated-password');
    const spanGeneratedEntropy = document.getElementById('generated-entropy');
    const themeLoading = document.getElementById('theme-loading');
    const themeDictInfo = document.getElementById('theme-dictionary-info');
    const wordsChips = document.getElementById('words-chips');

    // ========================================================================
    // 3. REFERENCIAS DEL DOM - MÓDULO 3: CREADOR INTERACTIVO DE CONTRASEÑA
    // ========================================================================
    const inputCreatorPassword = document.getElementById('creator-password');
    const btnToggleVisibility = document.getElementById('toggle-creator-visibility');
    const creatorProgressBar = document.getElementById('creator-progress-bar');
    const creatorPercentLabel = document.getElementById('creator-percent-label');
    const creatorEntropyLabel = document.getElementById('creator-entropy-label');
    const creatorLevelLabel = document.getElementById('creator-level-label');
    const creatorSuggestions = document.getElementById('creator-suggestions');
    const strengthProgressbar = document.getElementById('strength-progressbar');

    // ========================================================================
    // CONTROLADOR - MÓDULO 1: ANALIZAR ENTROPÍA ESTÁTICA
    // ========================================================================
    function handleAnalyze() {
        const password = inputPassword.value.trim();

        if (!password) {
            alert('Input requerido: Ingresa una contraseña para analizar su entropía.');
            inputPassword.focus();
            return;
        }

        // Consumo de la función expuesta globalmente por entropy.js
        const result = window.calculateEntropy(password);

        spanEntropyResult.textContent = result.entropy.toFixed(2);
        spanSecurityLevel.textContent = result.classification;

        // Inyección de estilos de clasificación
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
    }

    btnAnalyze.addEventListener('click', handleAnalyze);
    inputPassword.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            handleAnalyze();
        }
    });

    // ========================================================================
    // CONTROLADOR - MÓDULO 2: GENERADOR TEMÁTICO DINÁMICO (GEMINI / MOCK)
    // ========================================================================
    async function handleGenerateThematicPassphrase() {
        const theme = inputTheme.value.trim();

        if (!theme) {
            alert('Por favor ingresa un tema libre (ej. Fortnite, Ciberseguridad, Espacio, Anime...).');
            inputTheme.focus();
            return;
        }

        // Estado visual: Cargando...
        btnGenerate.disabled = true;
        const originalBtnText = btnGenerate.textContent;
        btnGenerate.textContent = 'Cargando...';
        themeLoading.classList.remove('hidden');
        spanGeneratedPassword.textContent = 'Extrayendo diccionario con IA...';
        spanGeneratedEntropy.textContent = '...';
        themeDictInfo.classList.add('hidden');

        try {
            // 1. Llamada asíncrona a la API de Gemini (window.ai o Mock Asíncrono de 20 palabras)
            const dynamicDictionary = await window.fetchThematicDictionary(theme);

            if (!Array.isArray(dynamicDictionary) || dynamicDictionary.length < 2) {
                throw new Error('El servicio de IA devolvió un diccionario insuficiente.');
            }

            // 2. Pasar el arreglo al método generatePassphrase existente (Diceware model intacto)
            const result = window.generatePassphrase(dynamicDictionary);

            spanGeneratedPassword.textContent = result.password;
            spanGeneratedEntropy.textContent = result.entropy.toFixed(2);

            // 3. Renderizar las palabras temáticas extraídas
            wordsChips.innerHTML = '';
            dynamicDictionary.forEach((word) => {
                const chip = document.createElement('span');
                chip.className = 'word-chip';
                chip.textContent = word;
                wordsChips.appendChild(chip);
            });
            themeDictInfo.classList.remove('hidden');

        } catch (error) {
            console.error('[Thematic Generator Exception]', error);
            spanGeneratedPassword.textContent = 'Error al generar';
            spanGeneratedEntropy.textContent = '0';
            alert(`Ocurrió un error al generar el diccionario temático: ${error.message || error}`);
        } finally {
            // Restaurar estado visual interactivo
            btnGenerate.disabled = false;
            btnGenerate.textContent = originalBtnText;
            themeLoading.classList.add('hidden');
        }
    }

    btnGenerate.addEventListener('click', handleGenerateThematicPassphrase);
    inputTheme.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            handleGenerateThematicPassphrase();
        }
    });

    // ========================================================================
    // CONTROLADOR - MÓDULO 3: CREADOR DE CONTRASEÑA SEGURO (INPUT EVENT)
    // ========================================================================

    // Toggle para visualizar/ocultar contraseña en texto plano
    btnToggleVisibility.addEventListener('click', () => {
        const isPassword = inputCreatorPassword.type === 'password';
        inputCreatorPassword.type = isPassword ? 'text' : 'password';
        btnToggleVisibility.textContent = isPassword ? '🙈' : '👁️';
        btnToggleVisibility.title = isPassword ? 'Ocultar contraseña' : 'Mostrar contraseña';
        inputCreatorPassword.focus();
    });

    /**
     * Evalúa la contraseña en tiempo real ante cada pulsación de tecla.
     * Utiliza STRICTLY un event listener 'input' (no click).
     */
    inputCreatorPassword.addEventListener('input', (event) => {
        const password = event.target.value;

        // 1. Evaluación matemática de entropía de Shannon mediante window.calculateEntropy
        const result = window.calculateEntropy(password);

        // Caso: Cadena vacía
        if (!password || password.length === 0) {
            creatorProgressBar.style.width = '0%';
            creatorProgressBar.style.backgroundColor = '#ccc';
            creatorPercentLabel.textContent = '0%';
            creatorEntropyLabel.textContent = '0.00';
            creatorLevelLabel.textContent = 'Débil';
            creatorLevelLabel.style.color = '#dc3545';
            strengthProgressbar.setAttribute('aria-valuenow', '0');

            creatorSuggestions.innerHTML = `
                <li class="suggestion-item info">Comienza a escribir una contraseña para evaluarla en tiempo real.</li>
            `;
            return;
        }

        // 2. Mapeo probabilístico a porcentaje visual (0 a 100%)
        // Tomamos 100 bits como el 100% de la barra de seguridad (inviabilidad matemática de fuerza bruta)
        const percent = Math.min(100, Math.max(0, Math.round((result.entropy / 100) * 100)));
        creatorProgressBar.style.width = `${percent}%`;
        creatorPercentLabel.textContent = `${percent}%`;
        creatorEntropyLabel.textContent = result.entropy.toFixed(2);
        creatorLevelLabel.textContent = result.classification;
        strengthProgressbar.setAttribute('aria-valuenow', String(percent));

        // 3. Código de color reactivo según la clasificación de entropía
        let barColor = '#dc3545'; // Rojo (Débil: < 60 bits)
        if (result.classification === 'Fuerte') {
            barColor = '#fd7e14'; // Naranja (Fuerte: 60 - 79.99 bits)
        } else if (result.classification === 'Segura') {
            barColor = '#198754'; // Verde (Segura: >= 80 bits)
        }
        creatorProgressBar.style.backgroundColor = barColor;
        creatorLevelLabel.style.color = barColor;

        // 4. Generación de sugerencias dinámicas según faltantes
        const length = password.length;
        const hasLower = /[a-z]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasDigits = /[0-9]/.test(password);
        const hasSymbols = /[^a-zA-Z0-9]/.test(password);

        const suggestions = [];

        // Regla: Longitud para mitigación de fuerza bruta
        if (length < 8) {
            suggestions.push({
                type: 'danger',
                text: `La longitud actual (${length} caracteres) es muy corta para mitigar fuerza bruta. Se requiere un mínimo de 12 a 16 caracteres.`
            });
        } else if (length < 12) {
            suggestions.push({
                type: 'warning',
                text: `Longitud aceptable (${length} caracteres), pero vulnerable a cómputo paralelo masivo. Extiéndela a 14 o más caracteres.`
            });
        }

        // Regla: Expansión del espacio probabilístico por símbolos
        if (!hasSymbols) {
            suggestions.push({
                type: 'warning',
                text: 'Añade símbolos especiales (!@#$%...) para duplicar el espacio probabilístico (+33 estados por carácter).'
            });
        }

        // Regla: Expansión de mayúsculas
        if (!hasUpper) {
            suggestions.push({
                type: 'warning',
                text: 'Añade letras mayúsculas [A-Z] para aumentar la cardinalidad (+26 estados por carácter).'
            });
        }

        // Regla: Expansión de minúsculas
        if (!hasLower) {
            suggestions.push({
                type: 'warning',
                text: 'Añade letras minúsculas [a-z] para diversificar el alfabeto base (+26 estados).'
            });
        }

        // Regla: Expansión de dígitos
        if (!hasDigits) {
            suggestions.push({
                type: 'warning',
                text: 'Añade dígitos numéricos [0-9] para incrementar las combinaciones del espacio muestral (+10 estados).'
            });
        }

        // Regla: Evaluación de la cota de entropía
        if (result.entropy < 60) {
            suggestions.push({
                type: 'danger',
                text: `Entropía crítica (${result.entropy.toFixed(2)} bits): susceptible a ataques offline mediante tablas hash y clústeres GPU.`
            });
        } else if (result.entropy >= 80) {
            suggestions.push({
                type: 'success',
                text: `¡Nivel de entropía excelente (${result.entropy.toFixed(2)} bits)! Cumple los estándares NIST SP 800-63B frente a fuerza bruta.`
            });
        }

        // Renderizado en el DOM de la lista de sugerencias
        creatorSuggestions.innerHTML = '';
        if (suggestions.length === 0) {
            const li = document.createElement('li');
            li.className = 'suggestion-item success';
            li.textContent = '¡Contraseña balanceada! Buena longitud, diversidad de caracteres y alta entropía de Shannon.';
            creatorSuggestions.appendChild(li);
        } else {
            suggestions.forEach((item) => {
                const li = document.createElement('li');
                li.className = `suggestion-item ${item.type}`;
                li.textContent = item.text;
                creatorSuggestions.appendChild(li);
            });
        }
    });
});
