package com.example.semana9;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.function.LongSupplier;

/**
 * Defensa contra fuerza bruta: bloqueo progresivo por nombre de usuario.
 *
 * - Se permiten {@link #MAX_ATTEMPTS} intentos seguidos. Al llegar al límite el usuario queda
 *   bloqueado {@link #BASE_LOCK_MS}; cada intento posterior tras expirar el bloqueo lo duplica,
 *   hasta {@link #MAX_LOCK_MS}. Un login correcto reinicia el contador.
 * - El intento se CUENTA ANTES de verificar la contraseña (beginAttempt), de modo que intentos
 *   en paralelo no pueden saltarse el límite.
 * - Se lleva la cuenta por el nombre ENVIADO (sin mirar si existe), así una cuenta inexistente
 *   se bloquea igual que una real y el bloqueo no sirve para enumerar usuarios.
 * - Mayúsculas y espacios no crean contadores nuevos ("Admin" == " admin ").
 * - El nombre no se guarda en claro: la clave es un hash SHA-256 del nombre normalizado.
 *
 * No depende de Android para poder probarse en la JVM.
 * Límite conocido: usa el reloj del dispositivo; adelantar la hora salta el bloqueo.
 */
public class LoginAttemptGuard {

    static final int MAX_ATTEMPTS = 5;
    static final long BASE_LOCK_MS = 30_000L;
    static final long MAX_LOCK_MS = 900_000L;

    /** Compartido por todas las instancias para que sean atómicas sobre el mismo almacén. */
    private static final Object LOCK = new Object();

    private final AttemptStore store;
    private final LongSupplier clock;

    public LoginAttemptGuard(AttemptStore store, LongSupplier clock) {
        this.store = store;
        this.clock = clock;
    }

    /**
     * Debe llamarse ANTES de verificar la contraseña.
     * @return 0 si el intento está permitido (y ya quedó contado), o los ms restantes de bloqueo.
     */
    public long beginAttempt(String username) {
        synchronized (LOCK) {
            String key = keyFor(username);
            long now = clock.getAsLong();
            AttemptStore.State s = store.load(key);
            long remaining = remaining(s, now);
            if (remaining > 0) {
                return remaining; // bloqueado: no se cuenta ni se verifica nada
            }
            s.failures++;
            if (s.failures >= MAX_ATTEMPTS) {
                int level = Math.min(s.failures - MAX_ATTEMPTS, 20);
                s.lockUntil = now + Math.min(BASE_LOCK_MS << level, MAX_LOCK_MS);
            }
            store.save(key, s);
            return 0;
        }
    }

    /** Login correcto: se olvidan los intentos fallidos y cualquier bloqueo. */
    public void recordSuccess(String username) {
        synchronized (LOCK) {
            store.clear(keyFor(username));
        }
    }

    /** @return ms que faltan para poder reintentar (0 si no está bloqueado). Solo lectura. */
    public long remainingLockMs(String username) {
        synchronized (LOCK) {
            return remaining(store.load(keyFor(username)), clock.getAsLong());
        }
    }

    private static long remaining(AttemptStore.State s, long now) {
        if (s.lockUntil <= now) {
            return 0;
        }
        // Si atrasan el reloj, el bloqueo no puede durar más que el máximo.
        return Math.min(s.lockUntil - now, MAX_LOCK_MS);
    }

    static String keyFor(String username) {
        String normalized = username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
        try {
            byte[] d = MessageDigest.getInstance("SHA-256")
                    .digest(normalized.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder("u");
            for (int i = 0; i < 16; i++) {
                sb.append(String.format("%02x", d[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 no disponible", e);
        }
    }
}
