package com.example.semana9;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.google.android.material.textfield.TextInputEditText;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;

/**
 * Pruebas de fuerza bruta contra el login REAL: base de datos SQLite con PBKDF2, bloqueo
 * persistido en SharedPreferences y pantalla de login. Un atacante simulado lanza diccionarios
 * de contraseñas y se comprueba cuántas llegan a verificarse.
 *
 * Los mensajes de aserción no incluyen contraseñas.
 *
 * Ejecutar con:  ./gradlew connectedDebugAndroidTest
 */
@RunWith(AndroidJUnit4.class)
public class BruteForceLoginInstrumentedTest {

    private static final String DB_NAME = "semana9.db";
    private static final String USER = "victima_bf";
    private static final String PASSWORD = "Cl4ve-Real-BF-7731";
    private static final int MAX = LoginAttemptGuard.MAX_ATTEMPTS;

    private Context ctx;
    private DatabaseHelper helper;
    private AtomicLong now;
    private AtomicInteger verifications;

    @Before
    public void setUp() {
        ctx = InstrumentationRegistry.getInstrumentation().getTargetContext();
        cleanState();
        helper = new DatabaseHelper(ctx);
        helper.registerUser(USER, PASSWORD);
        now = new AtomicLong(System.currentTimeMillis());
        verifications = new AtomicInteger();
    }

    @After
    public void tearDown() {
        helper.close();
        cleanState();
    }

    private void cleanState() {
        ctx.deleteDatabase(DB_NAME);
        ctx.deleteSharedPreferences("session");
        ctx.deleteSharedPreferences(PrefsAttemptStore.PREFS);
    }

    /** Servicio real (BD + prefs) con reloj controlable y contador de verificaciones. */
    private LoginService newService() {
        LoginAttemptGuard guard = new LoginAttemptGuard(new PrefsAttemptStore(ctx), now::get);
        return new LoginService((u, p) -> {
            verifications.incrementAndGet();
            return helper.login(u, p);
        }, guard);
    }

    // ------------------------------------------------------------ ataque de diccionario

    @Test
    public void diccionarioDe200ClavesSoloVerificaElMaximoDeIntentos() {
        LoginService service = newService();
        int locked = 0;
        for (int i = 0; i < 200; i++) {
            if (service.login(USER, "diccionario-" + i) == LoginService.LOCKED) locked++;
        }
        assertEquals("Solo MAX intentos deben llegar a PBKDF2", MAX, verifications.get());
        assertEquals(200 - MAX, locked);
    }

    @Test
    public void laClaveCorrectaEnMitadDelDiccionarioNoSeDescubre() {
        LoginService service = newService();
        boolean cracked = false;
        for (int i = 0; i < 100; i++) {
            String guess = (i == 50) ? PASSWORD : "palabra-" + i;
            if (service.login(USER, guess) > 0) {
                cracked = true;
                break;
            }
            now.addAndGet(100); // el atacante prueba 10 claves por segundo
        }
        assertFalse("El ataque de diccionario descubrió la contraseña", cracked);
    }

    @Test
    public void conElBloqueoActivoLaClaveCorrectaTambienEsRechazada() {
        LoginService service = newService();
        for (int i = 0; i < MAX; i++) service.login(USER, "mala-" + i);
        assertEquals(LoginService.LOCKED, service.login(USER, PASSWORD));

        now.addAndGet(LoginAttemptGuard.BASE_LOCK_MS);
        assertTrue("Tras expirar el bloqueo el usuario legítimo debe poder entrar",
                service.login(USER, PASSWORD) > 0);
    }

    @Test
    public void elBloqueoDuplicaTrasCadaFalloPosteriorYTieneTope() {
        LoginService service = newService();
        for (int i = 0; i < MAX; i++) service.login(USER, "mala-" + i);
        assertEquals(LoginAttemptGuard.BASE_LOCK_MS, service.remainingLockMs(USER));

        now.addAndGet(LoginAttemptGuard.BASE_LOCK_MS);
        service.login(USER, "mala-extra");
        assertEquals(2 * LoginAttemptGuard.BASE_LOCK_MS, service.remainingLockMs(USER));

        for (int i = 0; i < 10; i++) {
            now.addAndGet(service.remainingLockMs(USER));
            service.login(USER, "mala-" + i);
        }
        assertEquals("El bloqueo no debe superar el tope",
                LoginAttemptGuard.MAX_LOCK_MS, service.remainingLockMs(USER));
    }

    @Test
    public void unLoginCorrectoReiniciaElContador() {
        LoginService service = newService();
        for (int i = 0; i < MAX - 1; i++) service.login(USER, "mala-" + i);
        assertTrue(service.login(USER, PASSWORD) > 0);
        verifications.set(0);
        for (int i = 0; i < 50; i++) service.login(USER, "otra-" + i);
        assertEquals("Tras un éxito se recuperan los MAX intentos", MAX, verifications.get());
    }

    // ------------------------------------------------------- persistencia y aislamiento

    @Test
    public void elBloqueoSobreviveAlReinicioDeLaApp() {
        LoginService first = newService();
        for (int i = 0; i < MAX; i++) first.login(USER, "mala-" + i);

        // "Reinicio": servicio y guard completamente nuevos sobre las mismas preferencias.
        LoginService afterRestart = newService();
        assertTrue("El bloqueo debe persistir tras reiniciar", afterRestart.remainingLockMs(USER) > 0);
        assertEquals(LoginService.LOCKED, afterRestart.login(USER, PASSWORD));
    }

    @Test
    public void mayusculasYEspaciosNoDanIntentosNuevosContraLaBaseDeDatosReal() {
        LoginService service = newService();
        String[] variants = {USER, USER.toUpperCase(), "  " + USER + " ", "Victima_BF"};
        for (int i = 0; i < 40; i++) service.login(variants[i % variants.length], "g" + i);
        assertEquals(MAX, verifications.get());
    }

    @Test
    public void usuarioInexistenteSeBloqueaIgualQueUnoReal() {
        LoginService service = newService();
        int ghostVerified = 0;
        for (int i = 0; i < 30; i++) {
            if (service.login("fantasma_inexistente", "g" + i) != LoginService.LOCKED) ghostVerified++;
        }
        verifications.set(0);
        for (int i = 0; i < 30; i++) service.login(USER, "g" + i);
        assertEquals("Cuenta real e inexistente deben bloquearse con el mismo número de intentos",
                verifications.get(), ghostVerified);
    }

    @Test
    public void elBloqueoDeUnUsuarioNoAfectaAOtros() {
        helper.registerUser("otro_usuario_bf", PASSWORD);
        LoginService service = newService();
        for (int i = 0; i < MAX; i++) service.login(USER, "mala-" + i);
        assertEquals(LoginService.LOCKED, service.login(USER, "x"));
        assertTrue(service.login("otro_usuario_bf", PASSWORD) > 0);
    }

    @Test
    public void ataqueEnParaleloNoSuperaElLimiteContraLaBaseDeDatosReal() throws Exception {
        final LoginService service = newService();
        final int threads = 8;
        final CountDownLatch go = new CountDownLatch(1);
        final CountDownLatch done = new CountDownLatch(threads);
        for (int t = 0; t < threads; t++) {
            final int id = t;
            new Thread(() -> {
                try {
                    go.await();
                    for (int i = 0; i < 25; i++) service.login(USER, "p" + id + "-" + i);
                } catch (InterruptedException ignored) {
                } finally {
                    done.countDown();
                }
            }).start();
        }
        go.countDown();
        assertTrue("El ataque paralelo no terminó", done.await(60, java.util.concurrent.TimeUnit.SECONDS));
        assertTrue("Paralelismo saltó el límite: " + verifications.get() + " verificaciones",
                verifications.get() <= MAX);
    }

    /** Un intento bloqueado no debe pagar el coste de PBKDF2: no sirve para agotar la CPU. */
    @Test
    public void losIntentosBloqueadosSonBaratos() {
        LoginService service = newService();
        for (int i = 0; i < MAX; i++) service.login(USER, "mala-" + i);

        long start = System.nanoTime();
        for (int i = 0; i < 200; i++) service.login(USER, "bloqueado-" + i);
        long ms = (System.nanoTime() - start) / 1_000_000;
        assertEquals("No debe verificarse nada durante el bloqueo", MAX, verifications.get());
        assertTrue("200 intentos bloqueados tardaron " + ms + " ms (deberían ser casi instantáneos)",
                ms < 3000);
    }

    // ---------------------------------------------------------------- fuga de datos del guard

    @Test
    public void elArchivoDelGuardNoContieneUsuarioNiContrasena() throws Exception {
        LoginService service = newService();
        for (int i = 0; i < 3; i++) service.login(USER, PASSWORD + "-mal");

        File prefs = new File(ctx.getDataDir(), "shared_prefs/" + PrefsAttemptStore.PREFS + ".xml");
        assertTrue("No se escribió el estado del guard", waitUntil(prefs::exists, 5000));
        String xml = new String(Files.readAllBytes(prefs.toPath()), StandardCharsets.UTF_8);
        assertFalse("El guard guarda el nombre de usuario en claro", xml.toLowerCase().contains(USER));
        assertFalse("El guard guarda la contraseña", xml.contains(PASSWORD));
    }

    // ------------------------------------------------------------------- pantalla de login

    /**
     * Ataque a través de la interfaz real: tras MAX fallos, incluso la contraseña correcta
     * tecleada en la pantalla de login no inicia sesión mientras dura el bloqueo.
     */
    @Test
    public void ui_tras5FallosLaClaveCorrectaNoIniciaSesion() {
        try (ActivityScenario<LoginActivity> scenario = ActivityScenario.launch(LoginActivity.class)) {
            for (int i = 0; i < MAX; i++) {
                submitLogin(scenario, USER, "intento-incorrecto-" + i);
                assertTrue("El intento " + (i + 1) + " no terminó",
                        waitUntil(() -> isLoginButtonEnabled(scenario), 20000));
            }
            LoginAttemptGuard guard = new LoginAttemptGuard(new PrefsAttemptStore(ctx), System::currentTimeMillis);
            assertTrue("Tras " + MAX + " fallos el usuario debe estar bloqueado",
                    guard.remainingLockMs(USER) > 0);

            // El atacante ahora acierta la contraseña, pero está bloqueado.
            submitLogin(scenario, USER, PASSWORD);
            sleep(1500); // margen para que un login indebido llegara a completarse
            assertFalse("Se inició sesión con la cuenta bloqueada", new SessionManager(ctx).isLoggedIn());
            assertTrue("El botón debe seguir habilitado (no se lanzó verificación)",
                    isLoginButtonEnabled(scenario));
        }
    }

    // ================================================================== utilidades

    private static void submitLogin(ActivityScenario<LoginActivity> scenario, String user, String password) {
        scenario.onActivity(a -> {
            ((TextInputEditText) a.findViewById(R.id.etUsername)).setText(user);
            ((TextInputEditText) a.findViewById(R.id.etPassword)).setText(password);
            a.findViewById(R.id.btnLogin).performClick();
        });
    }

    private static boolean isLoginButtonEnabled(ActivityScenario<LoginActivity> scenario) {
        boolean[] enabled = {false};
        scenario.onActivity(a -> enabled[0] = a.findViewById(R.id.btnLogin).isEnabled());
        return enabled[0];
    }

    private static boolean waitUntil(BooleanSupplier condition, long timeoutMs) {
        long end = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < end) {
            if (condition.getAsBoolean()) return true;
            sleep(100);
        }
        return condition.getAsBoolean();
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
