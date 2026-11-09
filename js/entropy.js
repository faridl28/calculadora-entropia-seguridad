/**
 * @fileoverview Núcleo Criptográfico de Entropía y Generador Diceware.
 * 
 * Implementación bajo principios SOLID y buenas prácticas de criptografía aplicada:
 * - CSPRNG mediante window.crypto.getRandomValues() con Rejection Sampling (eliminación de modulo bias).
 * - Calculadora de entropía de Shannon / Hartley basada en análisis dinámico de espacio de claves (R).
 * - Generador de passphrases temáticas bajo el modelo probabilístico de Diceware con mutaciones de alta entropía.
 * - Servicio dinámico asíncrono para obtención de diccionarios temáticos mediante IA (Gemini / window.ai / Mock).
 * 
 * @author Security Engineering Team
 * @license MIT
 */

'use strict';

// ============================================================================
// 1. CONSTANTES CRIPTOGRÁFICAS Y CONFIGURACIÓN (Inmutables)
// ============================================================================

/**
 * Cardinalidad estándar de los pools de caracteres para el cálculo de entropía de contraseñas.
 * R = |Pool de caracteres|
 */
const POOL_CARDINALITY = Object.freeze({
    LOWERCASE: 26,  // [a-z]
    UPPERCASE: 26,  // [A-Z]
    NUMBERS: 10,    // [0-9]
    SYMBOLS: 33     // Caracteres imprimibles ASCII de puntuación/símbolos y espacio
});

/**
 * Rangos de clasificación de seguridad NIST / OWASP según bits de entropía.
 */
const SECURITY_THRESHOLDS = Object.freeze({
    WEAK_MAX: 59.99,    // < 60 bits: Débil
    STRONG_MAX: 79.99,  // 60 - 79.99 bits: Fuerte
    SECURE_MIN: 80.00   // >= 80 bits: Segura
});

/**
 * Símbolos permitidos para mutaciones y separadores en passphrases.
 */
const SEPARATOR_SYMBOLS = Object.freeze([
    '!', '@', '#', '$', '%', '&', '*', '+', '-', '=', '?', '_', '~', '^'
]);

// ============================================================================
// 2. DICCIONARIOS TEMÁTICOS PRE-POBLADOS (Base / Fallback)
// ============================================================================

const THEMATIC_DICTIONARIES = Object.freeze({
    english: Object.freeze([
        'abyss', 'algorithm', 'altitude', 'amplitude', 'anchor', 'anomaly', 'aperture', 'archive',
        'artifact', 'asteroid', 'aurora', 'avalanche', 'bandwidth', 'bastion', 'beacon', 'binary',
        'biometric', 'blizzard', 'boulder', 'breach', 'cache', 'cascade', 'catalyst', 'cathedral',
        'celestial', 'channel', 'chimera', 'chronos', 'cipher', 'circuit', 'citadel', 'cluster',
        'compass', 'compiler', 'conduit', 'corridor', 'cosmic', 'crescent', 'crystal', 'curator',
        'cyber', 'cyclone', 'database', 'decimal', 'delta', 'density', 'dimension', 'dominion',
        'dynamic', 'eclipse', 'element', 'enigma', 'entropy', 'epoch', 'equation', 'equinox',
        'ether', 'expanse', 'fabric', 'falcon', 'firewall', 'firmware', 'fissure', 'flipper',
        'fractal', 'frontier', 'galaxy', 'gateway', 'genesis', 'geode', 'glacier', 'gravity',
        'gyroscope', 'habitat', 'harbor', 'hazard', 'horizon', 'hybrid', 'impact', 'impulse',
        'infinity', 'infrared', 'isolate', 'isotope', 'junction', 'kaleidoscope', 'kernel', 'kinetic',
        'labyrinth', 'latitude', 'legacy', 'luminary', 'magnetic', 'magnitude', 'matrix', 'meridian',
        'monolith', 'nebula', 'network', 'nexus', 'nucleus', 'oasis', 'obsidian', 'orbit',
        'paradox', 'payload', 'phantom', 'pinnacle', 'plasma', 'protocol', 'pulsar', 'quantum',
        'radiant', 'resonance', 'sanctuary', 'satellite', 'shadow', 'solstice', 'spectrum', 'summit',
        'synapse', 'tempest', 'terminal', 'texture', 'thermal', 'threshold', 'thunder', 'titan',
        'topology', 'trajectory', 'traverse', 'trident', 'universe', 'vacuum', 'valence', 'velocity',
        'vortex', 'whisper', 'zenith', 'zephyr'
    ]),

    spanish: Object.freeze([
        'abismo', 'alcazar', 'alfiler', 'alondra', 'alquimia', 'antorcha', 'arrecife', 'astillero',
        'aurora', 'azimut', 'baluarte', 'barbacana', 'bastion', 'bitacora', 'boreal', 'brujula',
        'cabina', 'calzada', 'camino', 'campanario', 'cantil', 'carabela', 'cascada', 'castillo',
        'catedral', 'caverna', 'centinela', 'ciclone', 'cipres', 'ciudadela', 'claridad', 'colina',
        'cometa', 'cordillera', 'crisol', 'cruzada', 'cuarzo', 'cumbre', 'delfin', 'deriva',
        'desierto', 'destino', 'diamante', 'dilema', 'dinamo', 'dragante', 'duna', 'eclipse',
        'embalse', 'enclave', 'enigma', 'escombro', 'esmeralda', 'espolon', 'estela', 'estrella',
        'farallon', 'faro', 'filamento', 'fluvial', 'fortaleza', 'frescor', 'frontera', 'galerna',
        'glaciar', 'granito', 'guepardo', 'halcon', 'horizonte', 'huracan', 'imperio', 'isla',
        'laberinto', 'laguna', 'legado', 'leopardo', 'licantropo', 'limite', 'lucero', 'madrugada',
        'manantial', 'marisma', 'marmol', 'meseta', 'mirador', 'monolito', 'muralla', 'naufragio',
        'neblina', 'nevada', 'nodriza', 'oasis', 'oceano', 'olivo', 'orbita', 'origen',
        'palacio', 'paramo', 'peninsula', 'penumbra', 'pergamino', 'piramide', 'planicie', 'plenario',
        'pradera', 'quimera', 'radiante', 'refugio', 'relicario', 'relampago', 'resquicio', 'riachuelo',
        'roble', 'sabana', 'sagrado', 'salitre', 'sendero', 'serenata', 'sideral', 'sierra',
        'silencio', 'solsticio', 'sombra', 'talud', 'tempestad', 'timonel', 'torbellino', 'torrente',
        'travesia', 'trinchera', 'tsunami', 'umbral', 'valle', 'vanguardia', 'velero', 'ventisca',
        'vereda', 'vestigio', 'volcan', 'vortice', 'zafiro', 'zenit'
    ])
});

// ============================================================================
// 3. CAPA DE CRIPTOGRAFÍA: CSPRNG (Single Responsibility Principle)
// ============================================================================

/**
 * Servicio de Generación de Números Pseudoaleatorios Criptográficamente Seguros (CSPRNG).
 * Implementa rejection sampling para erradicar el sesgo de módulo (modulo bias).
 */
class CryptoService {
    /**
     * Obtiene la instancia de Web Crypto disponible.
     * @returns {Crypto}
     * @throws {Error} Si no existe soporte criptográfico en el entorno.
     */
    static getCrypto() {
        const cryptoInstance = (typeof window !== 'undefined' && (window.crypto || window.msCrypto)) ||
            (typeof globalThis !== 'undefined' && globalThis.crypto);

        if (!cryptoInstance || typeof cryptoInstance.getRandomValues !== 'function') {
            throw new Error('[Security Exception] CSPRNG no disponible: window.crypto.getRandomValues es requerido.');
        }
        return cryptoInstance;
    }

    /**
     * Genera un entero aleatorio uniforme en el intervalo semiabierto [0, max).
     * Aplica Rejection Sampling para garantizar distribución uniforme perfecta.
     * 
     * @param {number} max - Límite superior exclusivo (debe ser entero positivo).
     * @returns {number} Entero aleatorio seguro en [0, max - 1].
     */
    static getRandomInt(max) {
        if (!Number.isInteger(max) || max <= 0) {
            throw new RangeError('El parámetro max debe ser un entero estrictamente positivo.');
        }
        if (max === 1) return 0;

        const crypto = this.getCrypto();
        const buffer = new Uint32Array(1);
        const maxUint32 = 0x100000000; // 2^32
        // Mayor múltiplo de max menor o igual a 2^32
        const limit = Math.floor(maxUint32 / max) * max;

        while (true) {
            crypto.getRandomValues(buffer);
            const candidate = buffer[0];
            // Se rechazan los valores en la zona sesgada
            if (candidate < limit) {
                return candidate % max;
            }
        }
    }

    /**
     * Genera un entero uniforme dentro del rango inclusivo [min, max].
     * 
     * @param {number} min - Límite inferior inclusivo.
     * @param {number} max - Límite superior inclusivo.
     * @returns {number}
     */
    static getRandomRange(min, max) {
        if (min > max) {
            throw new RangeError('min no puede ser mayor que max.');
        }
        const span = (max - min) + 1;
        return min + this.getRandomInt(span);
    }

    /**
     * Selecciona un elemento aleatorio uniforme de un arreglo.
     * 
     * @template T
     * @param {readonly T[]} array - Arreglo de elementos.
     * @returns {T} Elemento seleccionado aleatoriamente.
     */
    static pickRandom(array) {
        if (!Array.isArray(array) || array.length === 0) {
            throw new TypeError('Se requiere un arreglo no vacío.');
        }
        const index = this.getRandomInt(array.length);
        return array[index];
    }
}

// ============================================================================
// 4. ANALIZADOR DE POOL DE CARACTERES (Single Responsibility)
// ============================================================================

/**
 * Evalúa dinámicamente el espacio de caracteres (R) presente en un string.
 */
class CharacterPoolAnalyzer {
    /**
     * Inspecciona los conjuntos presentes en el password y computa la cardinalidad total del pool.
     * 
     * @param {string} password - Cadena a analizar.
     * @returns {{
     *   poolSize: number,
     *   hasLower: boolean,
     *   hasUpper: boolean,
     *   hasDigits: boolean,
     *   hasSymbols: boolean
     * }}
     */
    static analyze(password) {
        if (typeof password !== 'string' || password.length === 0) {
            return {
                poolSize: 0,
                hasLower: false,
                hasUpper: false,
                hasDigits: false,
                hasSymbols: false
            };
        }

        const hasLower = /[a-z]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasDigits = /[0-9]/.test(password);
        // Cualquier carácter que no sea alfanumérico ASCII básico califica como símbolo/carácter especial
        const hasSymbols = /[^a-zA-Z0-9]/.test(password);

        let poolSize = 0;
        if (hasLower) poolSize += POOL_CARDINALITY.LOWERCASE;
        if (hasUpper) poolSize += POOL_CARDINALITY.UPPERCASE;
        if (hasDigits) poolSize += POOL_CARDINALITY.NUMBERS;
        if (hasSymbols) poolSize += POOL_CARDINALITY.SYMBOLS;

        return {
            poolSize,
            hasLower,
            hasUpper,
            hasDigits,
            hasSymbols
        };
    }
}

// ============================================================================
// 5. CALCULADORA DE ENTROPÍA DE SHANNON (Single Responsibility)
// ============================================================================

/**
 * Calculador de entropía de contraseñas bajo la fórmula de Shannon / Hartley:
 * E = L * log2(R)
 */
class ShannonEntropyCalculator {
    /**
     * Clasifica el nivel de seguridad basado en los bits de entropía según estándares de la industria.
     * 
     * @param {number} entropy - Bits de entropía.
     * @returns {'Débil' | 'Fuerte' | 'Segura'}
     */
    static classify(entropy) {
        if (entropy < 60) {
            return 'Débil';
        } else if (entropy < 80) {
            return 'Fuerte';
        } else {
            return 'Segura';
        }
    }

    /**
     * Calcula los bits de entropía para una contraseña determinada.
     * 
     * @param {string} password - Contraseña a evaluar.
     * @returns {{
     *   entropy: number,
     *   classification: 'Débil' | 'Fuerte' | 'Segura',
     *   length: number,
     *   poolSize: number
     * }}
     */
    static calculate(password) {
        if (typeof password !== 'string' || password.length === 0) {
            return {
                entropy: 0.00,
                classification: 'Débil',
                length: 0,
                poolSize: 0
            };
        }

        const length = password.length;
        const { poolSize } = CharacterPoolAnalyzer.analyze(password);

        if (poolSize === 0) {
            return {
                entropy: 0.00,
                classification: 'Débil',
                length,
                poolSize: 0
            };
        }

        // Fórmula de Shannon / Hartley: E = L * log2(R)
        const rawEntropy = length * Math.log2(poolSize);
        const roundedEntropy = Number(rawEntropy.toFixed(2));
        const classification = this.classify(roundedEntropy);

        return {
            entropy: roundedEntropy,
            classification,
            length,
            poolSize
        };
    }
}

// ============================================================================
// 6. GENERADOR DE PASSPHRASES DICEWARE CON MUTACIONES (Open/Closed & DIP)
// ============================================================================

/**
 * Generador de contraseñas mnemotécnicas temáticas bajo el modelo probabilístico de Diceware.
 * E_total = (k * log2(N)) + E_mutaciones
 */
class DicewarePassphraseGenerator {
    /**
     * @param {typeof CryptoService} [cryptoProvider=CryptoService] - Proveedor de CSPRNG inyectable.
     */
    constructor(cryptoProvider = CryptoService) {
        this.crypto = cryptoProvider;
    }

    /**
     * Genera una mutación criptográfica: símbolo aleatorio + número aleatorio de 3 dígitos (100-999).
     * 
     * @returns {{
     *   separatorString: string,
     *   entropy: number
     * }}
     */
    generateMutation() {
        const symbol = this.crypto.pickRandom(SEPARATOR_SYMBOLS);
        // Número entre 100 y 999 (900 estados posibles) para evitar ambigüedad de padding
        const number = this.crypto.getRandomRange(100, 999);

        const symbolEntropy = Math.log2(SEPARATOR_SYMBOLS.length);
        const numberEntropy = Math.log2(900);
        const mutationEntropy = symbolEntropy + numberEntropy;

        return {
            separatorString: `${symbol}${number}`,
            entropy: mutationEntropy
        };
    }

    /**
     * Capitaliza la primera letra de una palabra (TitleCase) para legibilidad mnemotécnica.
     * @param {string} word
     * @returns {string}
     */
    formatWord(word) {
        if (!word) return '';
        return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
    }

    /**
     * Genera una passphrase temática garantizando un mínimo de 60 bits de entropía.
     * 
     * @param {readonly string[]} dictionary - Arreglo con el diccionario temático.
     * @param {Object} [options] - Parámetros de generación opcionales.
     * @param {number} [options.minWords=4] - Cantidad mínima de palabras a concatenar (>= 4).
     * @param {number} [options.targetEntropy=60.0] - Entropía mínima requerida en bits.
     * @returns {{
     *   password: string,
     *   entropy: number,
     *   details: {
     *     wordsCount: number,
     *     dictionarySize: number,
     *     wordsEntropy: number,
     *     mutationsEntropy: number,
     *     totalEntropy: number
     *   }
     * }}
     */
    generate(dictionary, options = {}) {
        if (!Array.isArray(dictionary) || dictionary.length < 2) {
            throw new TypeError('[Security Exception] El diccionario debe ser un arreglo de al menos 2 palabras.');
        }

        const minWords = Math.max(4, Number.isInteger(options.minWords) ? options.minWords : 4);
        const targetEntropy = typeof options.targetEntropy === 'number' ? options.targetEntropy : 60.0;
        const dictSize = dictionary.length;
        const wordEntropy = Math.log2(dictSize);

        // Pre-cálculo de entropía por mutación (símbolo + número de 3 dígitos)
        const mutationUnitEntropy = Math.log2(SEPARATOR_SYMBOLS.length) + Math.log2(900);

        // Determinamos la cantidad de palabras necesarias para garantizar targetEntropy (mínimo 4)
        let wordsCount = minWords;
        while (true) {
            const separatorSlots = wordsCount - 1;
            const projectedEntropy = (wordsCount * wordEntropy) + (separatorSlots * mutationUnitEntropy);
            if (projectedEntropy >= targetEntropy || wordsCount >= 16) {
                break;
            }
            wordsCount++;
        }

        // Selección segura de palabras usando CSPRNG
        const selectedWords = [];
        for (let i = 0; i < wordsCount; i++) {
            const rawWord = this.crypto.pickRandom(dictionary);
            selectedWords.push(this.formatWord(rawWord));
        }

        // Aplicación de mutaciones como separadores entre palabras
        let passphrase = selectedWords[0];
        let totalMutationEntropy = 0;

        for (let i = 1; i < selectedWords.length; i++) {
            const mutation = this.generateMutation();
            passphrase += `${mutation.separatorString}${selectedWords[i]}`;
            totalMutationEntropy += mutation.entropy;
        }

        const wordsTotalEntropy = wordsCount * wordEntropy;
        const totalEntropy = wordsTotalEntropy + totalMutationEntropy;
        const roundedEntropy = Number(totalEntropy.toFixed(2));

        return {
            password: passphrase,
            entropy: roundedEntropy,
            details: {
                wordsCount,
                dictionarySize: dictSize,
                wordsEntropy: Number(wordsTotalEntropy.toFixed(2)),
                mutationsEntropy: Number(totalMutationEntropy.toFixed(2)),
                totalEntropy: roundedEntropy
            }
        };
    }
}

// ============================================================================
// 7. SERVICIO DINÁMICO DE DICCIONARIOS TEMÁTICOS (Gemini API / window.ai / Mock)
// ============================================================================

/**
 * Servicio para la obtención dinámica y asíncrona de diccionarios temáticos mediante IA.
 * Soporta la API experimental window.ai (Gemini Nano en Chrome), llamadas REST o simulación asíncrona robusta.
 */
class DynamicDictionaryService {
    /**
     * Conjuntos curados de palabras temáticas para el fallback asíncrono de IA.
     */
    static get CURATED_FALLBACKS() {
        return {
            fortnite: [
                'vbucks', 'construccion', 'pico', 'tormenta', 'refugio', 'escudo', 'bajas',
                'llama', 'pase', 'victoria', 'battlebus', 'infiltrado', 'fusil', 'escopeta',
                'fortaleza', 'isla', 'campero', 'skin', 'baile', 'loot'
            ],
            minecraft: [
                'diamante', 'creeper', 'redstone', 'obsidiana', 'nether', 'ender', 'pico',
                'aldeano', 'espada', 'bloque', 'bioma', 'portal', 'mineria', 'crafteo',
                'antorcha', 'zombie', 'pocion', 'armadura', 'vagoneta', 'bastion'
            ],
            ciberseguridad: [
                'firewall', 'malware', 'phishing', 'criptografia', 'hash', 'exploit', 'token',
                'vulnerabilidad', 'honeypot', 'cifrado', 'protocolo', 'servidor', 'antivirus',
                'sandbox', 'payload', 'backdoor', 'inyeccion', 'proxy', 'privacidad', 'autenticacion'
            ],
            hacking: [
                'firewall', 'malware', 'phishing', 'criptografia', 'hash', 'exploit', 'token',
                'vulnerabilidad', 'honeypot', 'cifrado', 'protocolo', 'servidor', 'antivirus',
                'sandbox', 'payload', 'backdoor', 'inyeccion', 'proxy', 'privacidad', 'autenticacion'
            ],
            espacio: [
                'galaxia', 'nebulosa', 'asteroide', 'orbita', 'telescopio', 'pulsar', 'gravedad',
                'supernova', 'cosmos', 'constelacion', 'eclipse', 'planeta', 'cometa', 'quasar',
                'horizonte', 'vacio', 'solsticio', 'sideral', 'apolo', 'interestelar'
            ],
            futbol: [
                'bernabeu', 'delantero', 'porteria', 'gambeta', 'campeonato', 'penalti', 'corner',
                'arbitro', 'estadio', 'aficion', 'clasico', 'balon', 'trofeo', 'cabezazo',
                'regate', 'chilena', 'defensa', 'mediocampo', 'fueralugar', 'victoria'
            ],
            anime: [
                'katana', 'chakra', 'shinigami', 'bankai', 'saiyajin', 'senpai', 'nakama',
                'hokage', 'alquimista', 'titan', 'dragon', 'otaku', 'gundam', 'stand',
                'cosmo', 'kaiju', 'ninja', 'hunter', 'jinchuriki', 'akira'
            ],
            cocina: [
                'albahaca', 'azafran', 'baguette', 'balsamico', 'casserole', 'cebolla', 'cilantro',
                'croqueta', 'curcuma', 'deglasear', 'emulsion', 'escalope', 'fermentar', 'flambear',
                'gourmet', 'jengibre', 'marinar', 'merengue', 'miseplace', 'risotto'
            ],
            gaming: [
                'respawn', 'hitbox', 'checkpoint', 'pixel', 'arcade', 'consola', 'gameplay',
                'joystick', 'glitch', 'boss', 'speedrun', 'avatar', 'servidor', 'mision',
                'inventario', 'pocion', 'combate', 'calabozo', 'logro', 'combos'
            ]
        };
    }

    /**
     * Limpia y normaliza una palabra para uso seguro dentro del algoritmo Diceware.
     * @param {string} word
     * @returns {string}
     */
    static sanitizeWord(word) {
        if (!word) return '';
        return word
            .trim()
            .toLowerCase()
            .normalize('NFD')
            .replace(/[\u0300-\u036f]/g, '') // Elimina diacríticos
            .replace(/[^a-z0-9]/g, '');      // Conserva únicamente caracteres alfanuméricos limpios
    }

    /**
     * Extrae un diccionario temático dinámico de 20 palabras.
     * 1. Consulta la API local window.ai (Chrome Gemini Nano) si está disponible.
     * 2. Si no hay credenciales o soporte local, ejecuta un mock asíncrono con simulación de latencia de red.
     * 
     * @param {string} theme - Tema ingresado libremente por el usuario.
     * @returns {Promise<string[]>} Arreglo con 20 palabras temáticas únicas.
     */
    static async fetchThematicDictionary(theme) {
        if (!theme || typeof theme !== 'string' || !theme.trim()) {
            throw new Error('Debes ingresar un tema válido para extraer el diccionario.');
        }

        const cleanTheme = theme.trim().toLowerCase();

        // Intento 1: API nativa window.ai (Chrome Built-in AI)
        if (typeof window !== 'undefined' && window.ai && window.ai.languageModel) {
            try {
                const capabilities = await window.ai.languageModel.capabilities();
                if (capabilities && capabilities.available !== 'no') {
                    const session = await window.ai.languageModel.create({
                        systemPrompt: 'Eres un generador criptográfico de palabras para el modelo Diceware. Devuelve exactamente 20 palabras sustantivas o descriptivas en minúsculas separadas por comas, sin números ni texto introductorio.'
                    });
                    const prompt = `Genera 20 palabras clave relacionadas con el tema "${cleanTheme}". Formato: palabra1, palabra2, ...`;
                    const response = await session.prompt(prompt);
                    const parsed = response
                        .split(/[,\n\r]+/)
                        .map(w => this.sanitizeWord(w))
                        .filter(w => w.length >= 3);

                    if (parsed.length >= 20) {
                        return parsed.slice(0, 20);
                    }
                }
            } catch (aiErr) {
                console.warn('[Gemini AI] window.ai no disponible o restringido. Utilizando mock asíncrono seguro:', aiErr);
            }
        }

        // Intento 2: Mock de Asincronía Robusto (Simula extracción vía LLM/Gemini API con latencia)
        // Simulación de latencia de red de 750ms para reflejar el estado de "Cargando..."
        await new Promise(resolve => setTimeout(resolve, 750));

        // Búsqueda en los bancos temáticos curados de respaldo
        for (const [key, list] of Object.entries(this.CURATED_FALLBACKS)) {
            if (cleanTheme.includes(key) || key.includes(cleanTheme)) {
                return [...list];
            }
        }

        // Generador léxico dinámico procedimental para cualquier tema libre desconocido
        const base = this.sanitizeWord(cleanTheme) || 'clave';
        const semanticDescriptors = [
            'alfa', 'omega', 'nexus', 'core', 'vector', 'pulso', 'vortex', 'red',
            'base', 'prisma', 'eco', 'sigma', 'delta', 'origen', 'rango', 'flujo',
            'sector', 'nodo', 'sombra', 'titan'
        ];

        const generatedWords = semanticDescriptors.map(desc => `${base}${desc}`);
        return generatedWords;
    }
}

// ============================================================================
// 8. FACHADA / INTERFAZ PÚBLICA (Interface Segregation & Easy Consumption)
// ============================================================================

// Instancia singleton por defecto del generador
const defaultGenerator = new DicewarePassphraseGenerator();

/**
 * Calculadora de Entropía de Shannon para cualquier contraseña o cadena.
 * 
 * @param {string} password - Cadena a evaluar.
 * @returns {{ entropy: number, classification: 'Débil' | 'Fuerte' | 'Segura' }}
 */
function calculateEntropy(password) {
    const result = ShannonEntropyCalculator.calculate(password);
    return {
        entropy: result.entropy,
        classification: result.classification
    };
}

/**
 * Generador de Passphrases Temáticas con garantía de entropía mínima (>= 60 bits).
 * Acepta tanto un arreglo directo como la clave temática ('english', 'spanish').
 * 
 * @param {readonly string[] | string} dictionaryOrTheme - Arreglo con palabras o clave temática.
 * @param {Object} [options] - Parámetros de configuración opcionales.
 * @returns {{ password: string, entropy: number }}
 */
function generatePassphrase(dictionaryOrTheme, options = {}) {
    let dictionaryArray = dictionaryOrTheme;

    // Si se pasa el identificador temático como string, se resuelve desde los diccionarios base
    if (typeof dictionaryOrTheme === 'string') {
        const themeKey = dictionaryOrTheme.toLowerCase().trim();
        if (THEMATIC_DICTIONARIES[themeKey]) {
            dictionaryArray = THEMATIC_DICTIONARIES[themeKey];
        } else {
            throw new Error(`[Security Exception] Diccionario temático estático desconocido: "${dictionaryOrTheme}". Utiliza DynamicDictionaryService para temas libres.`);
        }
    }

    const result = defaultGenerator.generate(dictionaryArray, options);
    return {
        password: result.password,
        entropy: result.entropy
    };
}

/**
 * Obtiene un diccionario temático dinámico de 20 palabras mediante IA / Mock Asíncrono.
 * 
 * @param {string} theme - Nombre del tema libre (ej. 'Fortnite').
 * @returns {Promise<string[]>}
 */
async function fetchThematicDictionary(theme) {
    return await DynamicDictionaryService.fetchThematicDictionary(theme);
}

// ============================================================================
// 9. EXPORTACIÓN MODULAR Y NAVEGADOR
// ============================================================================

// Exposición en el espacio de nombres global del navegador (window / globalThis)
if (typeof window !== 'undefined') {
    window.calculateEntropy = calculateEntropy;
    window.generatePassphrase = generatePassphrase;
    window.fetchThematicDictionary = fetchThematicDictionary;
    window.THEMATIC_DICTIONARIES = THEMATIC_DICTIONARIES;

    // Objeto contenedor para acceso estructurado
    window.EntropySecurity = Object.freeze({
        calculateEntropy,
        generatePassphrase,
        fetchThematicDictionary,
        THEMATIC_DICTIONARIES,
        DynamicDictionaryService,
        CryptoService,
        CharacterPoolAnalyzer,
        ShannonEntropyCalculator,
        DicewarePassphraseGenerator,
        POOL_CARDINALITY,
        SECURITY_THRESHOLDS,
        SEPARATOR_SYMBOLS
    });
}

// Compatibilidad con CommonJS para entornos Node.js y pruebas automatizadas
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        calculateEntropy,
        generatePassphrase,
        fetchThematicDictionary,
        THEMATIC_DICTIONARIES,
        DynamicDictionaryService,
        CryptoService,
        CharacterPoolAnalyzer,
        ShannonEntropyCalculator,
        DicewarePassphraseGenerator,
        POOL_CARDINALITY,
        SECURITY_THRESHOLDS,
        SEPARATOR_SYMBOLS
    };
}
