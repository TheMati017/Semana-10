package com.example.semana9;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Pruebas de fuerza bruta contra el login, sin emulador: un atacante simulado lanza diccionarios
 * de contraseñas contra {@link LoginService} con un reloj controlable y un verificador falso
 * que cuenta cuántas veces se llegó a comprobar una contraseña.
 *
 * Ejecutar con:  ./gradlew testDebugUnitTest
 */
public class BruteForceLoginTest {

    private static final long SECOND = 1000L;
    private static final long HOUR = 3600 * SECOND;
    private static final long DAY = 24 * HOUR;
    private static final String VICTIM = "victima";
    private static final String REAL_PASSWORD = "clave-real-9Zq";

    // ----------------------------------------------------------------- infraestructura

    /** Almacén en memoria para no depender de Android. */
    private static class MemoryStore implements AttemptStore {
        private final Map<String, State> map = new HashMap<>();

        @Override
        public synchronized State load(String key) {
            State s = new State();
            State saved = map.get(key);
            if (saved != null) {
                s.failures = saved.failures;
                s.lockUntil = saved.lockUntil;
            }
            return s;
        }

        @Override
        public synchronized void save(String key, State s) {
            State copy = new State();
            copy.failures = s.failures;
            copy.lockUntil = s.lockUntil;
            map.put(key, copy);
        }

        @Override
        public synchronized void clear(String key) {
            map.remove(key);
        }
    }

    /** Servicio con verificador falso: solo VICTIM + REAL_PASSWORD es válido (id 1). */
    private static class Fixture {
        final AtomicLong now = new AtomicLong(1_700_000_000_000L);
        final AtomicInteger verifications = new AtomicInteger();
        final MemoryStore store = new MemoryStore();
        final LoginAttemptGuard guard = new LoginAttemptGuard(store, now::get);
        final LoginService service = new LoginService((u, p) -> {
            verifications.incrementAndGet();
            return u.trim().equalsIgnoreCase(VICTIM) && REAL_PASSWORD.equals(p) ? 1 : -1;
        }, guard);
    }

    // -------------------------------------------------------------- política de bloqueo

    @Test
    public void permiteExactamenteElMaximoDeIntentosYLuegoBloquea() {
        Fixture f = new Fixture();
        for (int i = 1; i <= LoginAttemptGuard.MAX_ATTEMPTS; i++) {
            assertEquals("Intento " + i + " debería verificarse", -1, f.service.login(VICTIM, "mala" + i));
        }
        assertEquals("El siguiente intento debe estar bloqueado", LoginService.LOCKED,
                f.service.login(VICTIM, "mala-extra"));
        assertEquals(LoginAttemptGuard.MAX_ATTEMPTS, f.verifications.get());
        assertEquals(LoginAttemptGuard.BASE_LOCK_MS, f.service.remainingLockMs(VICTIM));
    }

    @Test
    public void ataqueDeDiccionarioMasivoSoloVerificaElMaximoDeIntentos() {
        Fixture f = new Fixture();
        int locked = 0;
        for (int i = 0; i < 100_000; i++) {
            if (f.service.login(VICTIM, "palabra" + i) == LoginService.LOCKED) locked++;
        }
        assertEquals("Solo MAX_ATTEMPTS pueden llegar a comprobarse",
                LoginAttemptGuard.MAX_ATTEMPTS, f.verifications.get());
        assertEquals(100_000 - LoginAttemptGuard.MAX_ATTEMPTS, locked);
    }

    @Test
    public void laContrasenaCorrectaEsRechazadaMientrasDuraElBloqueo() {
        Fixture f = new Fixture();
        for (int i = 0; i < LoginAttemptGuard.MAX_ATTEMPTS; i++) f.service.login(VICTIM, "mala" + i);

        assertEquals("Con el bloqueo activo ni la clave correcta debe entrar",
                LoginService.LOCKED, f.service.login(VICTIM, REAL_PASSWORD));
        f.now.addAndGet(LoginAttemptGuard.BASE_LOCK_MS - 1);
        assertEquals(LoginService.LOCKED, f.service.login(VICTIM, REAL_PASSWORD));
        f.now.addAndGet(1); // el bloqueo expira justo ahora
        assertEquals("Pasado el bloqueo la clave correcta vuelve a funcionar",
                1, f.service.login(VICTIM, REAL_PASSWORD));
    }

    @Test
    public void elBloqueoCreceExponencialmenteHastaUnTope() {
        Fixture f = new Fixture();
        for (int i = 0; i < LoginAttemptGuard.MAX_ATTEMPTS; i++) f.service.login(VICTIM, "x");
        long expected = LoginAttemptGuard.BASE_LOCK_MS;
        assertEquals(expected, f.service.remainingLockMs(VICTIM));

        for (int round = 0; round < 12; round++) {
            f.now.addAndGet(f.service.remainingLockMs(VICTIM)); // espera a que expire
            assertEquals(0, f.service.remainingLockMs(VICTIM));
            f.service.login(VICTIM, "otra-mala");               // un intento fallido más
            expected = Math.min(expected * 2, LoginAttemptGuard.MAX_LOCK_MS);
            assertEquals("Ronda " + round, expected, f.service.remainingLockMs(VICTIM));
        }
        assertEquals("El bloqueo no puede superar el tope", LoginAttemptGuard.MAX_LOCK_MS, expected);
    }

    @Test
    public void unAtaqueContinuoDe24HorasEstaMuyLimitado() {
        Fixture f = new Fixture();
        long end = f.now.get() + DAY;
        // El atacante reintenta cada segundo durante 24 h, esperando a que expire cada bloqueo.
        while (f.now.get() < end) {
            f.service.login(VICTIM, "guess" + f.verifications.get());
            f.now.addAndGet(SECOND);
        }
        int guesses = f.verifications.get();
        assertTrue("En 24 h un atacante pudo probar " + guesses + " claves (máx. permitido 120)",
                guesses <= 120);
    }

    @Test
    public void unDiccionarioDeDiezMilClavesNoEncuentraLaCorrectaEnUnaHora() {
        Fixture f = new Fixture();
        String[] dictionary = new String[10_000];
        for (int i = 0; i < dictionary.length; i++) dictionary[i] = "pw" + i;
        dictionary[5_000] = REAL_PASSWORD; // la clave real está en medio del diccionario

        long end = f.now.get() + HOUR;
        boolean cracked = false;
        int next = 0;
        while (f.now.get() < end && next < dictionary.length) {
            if (f.service.login(VICTIM, dictionary[next]) == 1) {
                cracked = true;
                break;
            }
            next++;
            f.now.addAndGet(100); // 10 intentos por segundo
        }
        assertFalse("El atacante descubrió la contraseña en 1 hora", cracked);
        assertTrue("En 1 hora no debería verificar más de 20 claves: " + f.verifications.get(),
                f.verifications.get() <= 20);
    }

    // ------------------------------------------------------------- reinicio y aislamiento

    @Test
    public void unLoginCorrectoReiniciaElContador() {
        Fixture f = new Fixture();
        for (int i = 0; i < LoginAttemptGuard.MAX_ATTEMPTS - 1; i++) f.service.login(VICTIM, "mala");
        assertEquals(1, f.service.login(VICTIM, REAL_PASSWORD));

        // Tras el éxito se vuelve a disponer de todos los intentos.
        for (int i = 0; i < LoginAttemptGuard.MAX_ATTEMPTS; i++) {
            assertEquals(-1, f.service.login(VICTIM, "mala"));
        }
        assertEquals(LoginService.LOCKED, f.service.login(VICTIM, "mala"));
    }

    @Test
    public void elBloqueoEsPorUsuarioNoGlobal() {
        Fixture f = new Fixture();
        for (int i = 0; i < LoginAttemptGuard.MAX_ATTEMPTS; i++) f.service.login(VICTIM, "mala");
        assertEquals(LoginService.LOCKED, f.service.login(VICTIM, "mala"));
        assertEquals("Otro usuario no debe verse afectado", -1, f.service.login("otro_usuario", "mala"));
    }

    @Test
    public void cambiarMayusculasOEspaciosNoDaIntentosNuevos() {
        Fixture f = new Fixture();
        String[] variants = {"victima", "VICTIMA", " Victima ", "vIcTiMa", "victima\t", "VICTIMA "};
        int verified = 0;
        for (int i = 0; i < 60; i++) {
            if (f.service.login(variants[i % variants.length], "x" + i) != LoginService.LOCKED) verified++;
        }
        assertEquals("Las variantes del nombre comparten contador",
                LoginAttemptGuard.MAX_ATTEMPTS, verified);
    }

    /** Si el bloqueo de usuarios inexistentes fuese distinto, serviría para enumerar cuentas. */
    @Test
    public void unUsuarioInexistenteSeBloqueaIgualQueUnoReal() {
        Fixture real = new Fixture();
        Fixture ghost = new Fixture();
        int realVerified = 0;
        int ghostVerified = 0;
        for (int i = 0; i < 50; i++) {
            if (real.service.login(VICTIM, "g" + i) != LoginService.LOCKED) realVerified++;
            if (ghost.service.login("no_existe_jamas", "g" + i) != LoginService.LOCKED) ghostVerified++;
        }
        assertEquals("Mismo número de intentos para cuenta real e inexistente", realVerified, ghostVerified);
        assertEquals(real.service.remainingLockMs(VICTIM),
                ghost.service.remainingLockMs("no_existe_jamas"));
    }

    // ------------------------------------------------------------------ robustez

    @Test
    public void intentosEnParaleloNoSuperanElLimite() throws Exception {
        final Fixture f = new Fixture();
        final int threads = 16;
        final int attemptsPerThread = 200;
        final CountDownLatch ready = new CountDownLatch(threads);
        final CountDownLatch go = new CountDownLatch(1);
        final CountDownLatch done = new CountDownLatch(threads);
        for (int t = 0; t < threads; t++) {
            final int id = t;
            new Thread(() -> {
                ready.countDown();
                try {
                    go.await();
                    for (int i = 0; i < attemptsPerThread; i++) f.service.login(VICTIM, "t" + id + "-" + i);
                } catch (InterruptedException ignored) {
                } finally {
                    done.countDown();
                }
            }).start();
        }
        ready.await();
        go.countDown();
        done.await();
        assertTrue("Paralelismo saltó el límite: " + f.verifications.get() + " verificaciones",
                f.verifications.get() <= LoginAttemptGuard.MAX_ATTEMPTS);
    }

    @Test
    public void atrasarElRelojNoExtiendeElBloqueoMasAllaDelMaximo() {
        Fixture f = new Fixture();
        for (int i = 0; i < LoginAttemptGuard.MAX_ATTEMPTS; i++) f.service.login(VICTIM, "mala");
        f.now.addAndGet(-100 * DAY); // el usuario/atacante retrocede el reloj
        assertTrue(f.service.remainingLockMs(VICTIM) <= LoginAttemptGuard.MAX_LOCK_MS);
    }

    @Test
    public void elEstadoSeGuardaConClaveHasheadaSinElNombreEnClaro() {
        Fixture f = new Fixture();
        f.service.login("Nombre.Secreto", "x");
        for (String key : f.store.map.keySet()) {
            assertFalse("La clave del almacén no debe contener el nombre", key.toLowerCase().contains("secreto"));
        }
        assertEquals(1, f.store.map.size());
    }
}
