package com.example.semana9;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.system.Os;
import android.system.OsConstants;
import android.text.method.PasswordTransformationMethod;
import android.util.Base64;
import android.widget.TextView;

import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.google.android.material.textfield.TextInputEditText;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

/**
 * Pruebas de fuga de datos que se ejecutan en un dispositivo o emulador y miran lo que la
 * app realmente deja en disco, en logcat, en SharedPreferences y en la interfaz.
 *
 * REGLA DE ORO: ningún mensaje de aserción incluye la contraseña de prueba, para que un
 * fallo no cree por sí mismo una fuga en el reporte o en logcat.
 *
 * Ejecutar con:  ./gradlew connectedDebugAndroidTest
 */
@RunWith(AndroidJUnit4.class)
public class DataLeakInstrumentedTest {

    private static final String DB_NAME = "semana9.db";
    private static final String PREFS_NAME = "session";
    /** Valor centinela único: si aparece en cualquier sitio, es una fuga. */
    private static final String PASSWORD = "Tr0ub4dor&3-LEAKCHECK";
    private static final String USER = "leak_tester";

    private Context ctx;
    private DatabaseHelper helper;
    private SessionManager session;

    @Before
    public void setUp() {
        ctx = InstrumentationRegistry.getInstrumentation().getTargetContext();
        cleanState();
        helper = new DatabaseHelper(ctx);
        session = new SessionManager(ctx);
    }

    @After
    public void tearDown() {
        helper.close();
        cleanState();
    }

    private void cleanState() {
        ctx.deleteDatabase(DB_NAME);
        ctx.deleteSharedPreferences(PREFS_NAME);
        ctx.deleteSharedPreferences("login_guard"); // estado anti fuerza bruta
    }

    // ------------------------------------------------- 1. Contraseñas en la base de datos

    @Test
    public void bd_noGuardaLaContrasenaEnTextoPlanoEnNingunaColumna() {
        assertTrue(helper.registerUser(USER, PASSWORD) > 0);

        SQLiteDatabase db = helper.getReadableDatabase();
        int rows = 0;
        try (Cursor c = db.rawQuery("SELECT * FROM users", null)) {
            while (c.moveToNext()) {
                rows++;
                for (int i = 0; i < c.getColumnCount(); i++) {
                    String value = String.valueOf(c.getString(i));
                    assertFalse("Columna '" + c.getColumnName(i) + "' contiene la contraseña",
                            value.contains(PASSWORD));
                }
            }
        }
        assertEquals(1, rows);
    }

    @Test
    public void bd_hashYSaltTienenElFormatoEsperado() {
        helper.registerUser(USER, PASSWORD);
        try (Cursor c = helper.getReadableDatabase().rawQuery(
                "SELECT password_hash, salt FROM users WHERE username = ?", new String[]{USER})) {
            assertTrue(c.moveToFirst());
            byte[] hash = Base64.decode(c.getString(0), Base64.NO_WRAP);
            byte[] salt = Base64.decode(c.getString(1), Base64.NO_WRAP);
            assertEquals("El hash debe ser PBKDF2-HMAC-SHA256 de 256 bits", 32, hash.length);
            assertEquals("La salt debe ser de 128 bits", 16, salt.length);
            assertFalse("La salt no puede ser todo ceros", Arrays.equals(salt, new byte[16]));
        }
    }

    /** Sin salt única, dos usuarios con la misma clave tendrían el mismo hash (rainbow tables). */
    @Test
    public void bd_saltEsUnicaPorUsuario() {
        helper.registerUser("usuario_uno", PASSWORD);
        helper.registerUser("usuario_dos", PASSWORD);

        List<String> salts = new ArrayList<>();
        List<String> hashes = new ArrayList<>();
        try (Cursor c = helper.getReadableDatabase().rawQuery(
                "SELECT password_hash, salt FROM users", null)) {
            while (c.moveToNext()) {
                hashes.add(c.getString(0));
                salts.add(c.getString(1));
            }
        }
        assertEquals(2, hashes.size());
        assertNotEquals("Hash idéntico para la misma contraseña: falta salt única",
                hashes.get(0), hashes.get(1));
        assertNotEquals("Salt repetida entre usuarios", salts.get(0), salts.get(1));
    }

    // ---------------------------------------- 2. Búsqueda de la contraseña en TODO el disco

    /**
     * Recorre byte a byte todo el almacenamiento de la app (BD, -wal, -journal, prefs, files,
     * cache, almacenamiento externo) buscando la contraseña en claro, en Base64 o como hash
     * SHA-256 sin salt.
     */
    @Test
    public void disco_ningunArchivoContieneLaContrasena() throws Exception {
        helper.registerUser(USER, PASSWORD);
        assertTrue(helper.login(USER, PASSWORD) > 0);
        session.saveSession(1, USER);
        awaitPrefsFlush();
        writePrivatePhotoLikeMainActivity();
        helper.close(); // fuerza checkpoint del WAL; igualmente se escanean -wal/-journal

        List<File> roots = new ArrayList<>();
        roots.add(ctx.getDataDir());
        addIfNotNull(roots, ctx.getExternalFilesDir(null));
        addIfNotNull(roots, ctx.getExternalCacheDir());

        List<String> leaks = new ArrayList<>();
        for (File root : roots) {
            scanForSecrets(root, secretNeedles(PASSWORD), leaks);
        }
        assertTrue("La contraseña aparece en estos archivos: " + leaks, leaks.isEmpty());
    }

    // ------------------------------------------------------------ 3. Sesión (SharedPreferences)

    @Test
    public void sesion_soloGuardaIdYUsuario_nuncaContrasenaNiHash() throws Exception {
        helper.registerUser(USER, PASSWORD);
        long id = helper.login(USER, PASSWORD);
        session.saveSession(id, USER);

        assertTrue(session.isLoggedIn());
        Set<String> keys = ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getAll().keySet();
        assertEquals("La sesión solo puede guardar user_id, username y login_at",
                new HashSet<>(Arrays.asList("user_id", "username", "login_at")), keys);

        File prefsFile = prefsFile();
        awaitFile(prefsFile);
        String xml = readFile(prefsFile);
        assertFalse(xml.contains(PASSWORD));
        try (Cursor c = helper.getReadableDatabase().rawQuery(
                "SELECT password_hash, salt FROM users", null)) {
            assertTrue(c.moveToFirst());
            assertFalse("El hash no debe copiarse a las preferencias", xml.contains(c.getString(0)));
            assertFalse("La salt no debe copiarse a las preferencias", xml.contains(c.getString(1)));
        }
    }

    @Test
    public void logout_borraTodosLosDatosDeSesion() throws Exception {
        session.saveSession(7, USER);
        awaitFile(prefsFile());

        session.logout();

        assertFalse(session.isLoggedIn());
        assertEquals("", session.getUsername());
        assertTrue("Deben borrarse todas las preferencias de sesión",
                ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).getAll().isEmpty());
        // apply() escribe en segundo plano: se espera a que el archivo ya no tenga el usuario.
        assertTrue("El nombre de usuario sigue en disco tras cerrar sesión",
                waitUntil(() -> !readFile(prefsFile()).contains(USER), 5000));
    }


    // ------------------------------------------------ 3b. Caducidad de sesión y tiempos de login

    private void writeRawSession(long loginAt) {
        ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
                .putLong("user_id", 1).putString("username", USER)
                .putLong("login_at", loginAt).commit();
    }

    @Test
    public void sesion_vigenteSigueAbierta() {
        session.saveSession(1, USER);
        assertTrue(session.isLoggedIn());
        assertEquals(USER, session.getUsername());
    }

    @Test
    public void sesion_vencidaSeCierraYSeBorra() {
        writeRawSession(System.currentTimeMillis()
                - java.util.concurrent.TimeUnit.DAYS.toMillis(SessionManager.SESSION_MAX_AGE_DAYS + 1));
        assertFalse("Una sesión vencida no debe seguir abierta", session.isLoggedIn());
        assertTrue("La sesión vencida debe borrarse",
                ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).getAll().isEmpty());
    }

    @Test
    public void sesion_sinFechaOConFechaFuturaSeCierra() {
        writeRawSession(0); // sesión de una versión antigua, sin fecha
        assertFalse(session.isLoggedIn());

        writeRawSession(System.currentTimeMillis() + java.util.concurrent.TimeUnit.DAYS.toMillis(365));
        assertFalse("Fecha futura (reloj manipulado) no debe mantener la sesión", session.isLoggedIn());
    }

    /**
     * Antes un usuario inexistente respondía en milisegundos y uno existente en cientos de ms.
     * Ahora ambos calculan PBKDF2, así que las medianas deben ser del mismo orden.
     */
    @Test
    public void login_tiempoSimilarParaUsuarioExistenteEInexistente() {
        helper.registerUser(USER, PASSWORD);
        helper.login(USER, "calentamiento"); // calienta JIT/caches
        helper.login("no_existe_nadie", "calentamiento");

        long known = medianNanos(5, () -> helper.login(USER, "clave-incorrecta"));
        long unknown = medianNanos(5, () -> helper.login("usuario_inexistente", "clave-incorrecta"));
        assertTrue("Usuario inexistente responde mucho más rápido (" + unknown / 1_000_000
                        + " ms vs " + known / 1_000_000 + " ms): se puede enumerar usuarios",
                unknown * 2 >= known);
    }

    private static long medianNanos(int runs, Runnable action) {
        long[] t = new long[runs];
        for (int i = 0; i < runs; i++) {
            long start = System.nanoTime();
            action.run();
            t[i] = System.nanoTime() - start;
        }
        Arrays.sort(t);
        return t[runs / 2];
    }

    // ------------------------------------------------------- 4. Permisos de archivos en disco

    /** Archivos legibles/escribibles por "otros" permitirían a otras apps leer los datos. */
    @Test
    public void permisos_archivosDeLaAppNoSonAccesiblesParaOtros() throws Exception {
        helper.registerUser(USER, PASSWORD);
        session.saveSession(1, USER);
        awaitPrefsFlush();
        File photo = writePrivatePhotoLikeMainActivity();

        List<File> files = new ArrayList<>();
        files.add(ctx.getDatabasePath(DB_NAME));
        files.add(prefsFile());
        files.add(photo);

        List<String> problemas = new ArrayList<>();
        for (File f : files) {
            if (!f.exists()) {
                problemas.add(f.getName() + " no existe (no se pudo verificar)");
                continue;
            }
            int mode = Os.stat(f.getAbsolutePath()).st_mode;
            int others = OsConstants.S_IROTH | OsConstants.S_IWOTH | OsConstants.S_IXOTH;
            if ((mode & others) != 0) {
                problemas.add(f.getName() + " con permisos para otros: 0" + Integer.toOctalString(mode & 0777));
            }
        }
        assertTrue("Archivos con permisos inseguros: " + problemas, problemas.isEmpty());
    }

    // --------------------------------------------------- 5. Inyección SQL y enumeración de usuarios

    @Test
    public void login_resisteInyeccionSql() {
        helper.registerUser(USER, PASSWORD);

        String[] payloads = {
                "' OR '1'='1", "' OR 1=1 --", "admin'--", "\" OR \"\"=\"", USER + "' --",
                USER + "'/*", "'; DROP TABLE users; --", "%", "_", USER.substring(0, 4) + "%",
                "' UNION SELECT 1,'x','y',0 --"
        };
        for (String payload : payloads) {
            assertEquals("Inyección en usuario aceptada: " + payload,
                    -1, helper.login(payload, "cualquiera"));
            assertEquals("Inyección en usuario+clave aceptada: " + payload,
                    -1, helper.login(payload, payload));
            assertEquals("Inyección en contraseña aceptada: " + payload,
                    -1, helper.login(USER, payload));
        }
        // La tabla sigue intacta y el usuario legítimo sigue entrando.
        assertTrue(helper.login(USER, PASSWORD) > 0);
    }

    @Test
    public void registro_guardaPayloadsSqlComoTextoLiteral() {
        String evil = "x'); DROP TABLE users; --";
        assertTrue(helper.registerUser(evil, PASSWORD) > 0);
        assertTrue(helper.usernameExists(evil));
        assertFalse(helper.usernameExists("x"));
        // La tabla sigue viva: se puede registrar y entrar con otro usuario.
        assertTrue(helper.registerUser(USER, PASSWORD) > 0);
        assertTrue(helper.login(USER, PASSWORD) > 0);
    }

    /** El login no debe revelar si falló el usuario o la contraseña. */
    @Test
    public void login_mismaRespuestaParaUsuarioInexistenteYContrasenaIncorrecta() {
        helper.registerUser(USER, PASSWORD);
        long wrongPassword = helper.login(USER, "otra-clave-incorrecta");
        long unknownUser = helper.login("usuario_que_no_existe", PASSWORD);
        assertEquals(wrongPassword, unknownUser);
        assertEquals(-1, wrongPassword);
    }

    // ------------------------------------------------------------------- 6. Logcat

    /** Se ejecuta el flujo de login fallido por la UI real y se revisa logcat. */
    @Test
    public void ui_loginFallidoNoCreaSesionNiRegistraLaContrasenaEnLogcat() throws Exception {
        try (ActivityScenario<LoginActivity> scenario = ActivityScenario.launch(LoginActivity.class)) {
            scenario.onActivity(a -> {
                ((TextInputEditText) a.findViewById(R.id.etUsername)).setText("nadie_registrado");
                ((TextInputEditText) a.findViewById(R.id.etPassword)).setText(PASSWORD);
                a.findViewById(R.id.btnLogin).performClick();
            });
            // El botón vuelve a habilitarse cuando el login (en hilo secundario) termina con error.
            assertTrue("El login no terminó a tiempo", waitUntil(() -> {
                boolean[] enabled = {false};
                scenario.onActivity(a -> enabled[0] = a.findViewById(R.id.btnLogin).isEnabled());
                return enabled[0];
            }, 15000));
        }
        assertFalse("Un login fallido no debe crear sesión", new SessionManager(ctx).isLoggedIn());

        String logcat = readLogcat();
        assertFalse("La contraseña aparece en logcat", logcat.contains(PASSWORD));
    }

    @Test
    public void logcat_flujoDeRegistroYLoginNoRegistraContrasena() throws Exception {
        helper.registerUser(USER, PASSWORD);
        helper.login(USER, PASSWORD);
        helper.login(USER, "incorrecta-" + PASSWORD);
        String logcat = readLogcat();
        assertFalse("La contraseña aparece en logcat", logcat.contains(PASSWORD));
        try (Cursor c = helper.getReadableDatabase().rawQuery(
                "SELECT password_hash FROM users", null)) {
            assertTrue(c.moveToFirst());
            assertFalse("El hash aparece en logcat", logcat.contains(c.getString(0)));
        }
    }

    // ------------------------------------------------------------------ 7. UI y acceso

    @Test
    public void ui_camposDeContrasenaMuestranPuntosNoTexto() {
        try (ActivityScenario<LoginActivity> sc = ActivityScenario.launch(LoginActivity.class)) {
            sc.onActivity(a -> assertTrue("Login: contraseña visible",
                    isMasked(a.findViewById(R.id.etPassword))));
        }
        try (ActivityScenario<RegisterActivity> sc = ActivityScenario.launch(RegisterActivity.class)) {
            sc.onActivity(a -> {
                assertTrue("Registro: contraseña visible", isMasked(a.findViewById(R.id.etPassword)));
                assertTrue("Registro: confirmación visible",
                        isMasked(a.findViewById(R.id.etConfirmPassword)));
            });
        }
    }

    /** Sin sesión, MainActivity no debe mostrar nada: redirige al login y se cierra. */
    @Test
    public void acceso_mainActivitySinSesionNoMuestraContenido() {
        assertFalse(new SessionManager(ctx).isLoggedIn());
        try (ActivityScenario<MainActivity> scenario = ActivityScenario.launch(MainActivity.class)) {
            assertTrue("MainActivity sigue abierta sin sesión iniciada",
                    waitUntil(() -> scenario.getState() == Lifecycle.State.DESTROYED, 8000));
        }
    }

    // ---------------------------------------------------- 8. Superficie expuesta (manifest fusionado)

    @SuppressWarnings("deprecation")
    @Test
    public void manifest_soloLoginActivityEstaExportada() throws Exception {
        PackageManager pm = ctx.getPackageManager();
        PackageInfo info = pm.getPackageInfo(ctx.getPackageName(),
                PackageManager.GET_ACTIVITIES | PackageManager.GET_SERVICES
                        | PackageManager.GET_RECEIVERS | PackageManager.GET_PROVIDERS);

        List<String> exportados = new ArrayList<>();
        // Solo componentes de ESTA app (las librerías de terceros traen los suyos).
        if (info.activities != null) {
            for (ActivityInfo a : info.activities) {
                if (a.name.startsWith(ctx.getPackageName()) && a.exported
                        && !a.name.endsWith(".LoginActivity")) exportados.add(a.name);
            }
        }
        if (info.receivers != null) {
            for (ActivityInfo r : info.receivers) {
                if (r.name.startsWith(ctx.getPackageName()) && r.exported) exportados.add(r.name);
            }
        }
        if (info.services != null) {
            for (ServiceInfo s : info.services) {
                if (s.name.startsWith(ctx.getPackageName()) && s.exported) exportados.add(s.name);
            }
        }
        if (info.providers != null) {
            for (ProviderInfo p : info.providers) {
                if (p.name.startsWith(ctx.getPackageName()) && p.exported) exportados.add(p.name);
            }
        }
        assertTrue("Componentes exportados innecesariamente: " + exportados, exportados.isEmpty());
    }

    /** Se comprueba el manifest FUSIONADO (una librería podría reactivar el backup). */
    @Test
    public void manifest_backupDesactivadoEnLaAppInstalada() {
        int flags = ctx.getApplicationInfo().flags;
        assertEquals("allowBackup debe estar desactivado: la BD y la sesión no deben salir del equipo",
                0, flags & ApplicationInfo.FLAG_ALLOW_BACKUP);
    }

    // ============================================================================ utilidades

    private File prefsFile() {
        return new File(ctx.getDataDir(), "shared_prefs/" + PREFS_NAME + ".xml");
    }

    /** Imita MainActivity.savePhotoAsync(): JPEG en getFilesDir(). */
    private File writePrivatePhotoLikeMainActivity() throws IOException {
        File photo = new File(ctx.getFilesDir(), "foto_leaktest.jpg");
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(photo)) {
            out.write(new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xD9});
        }
        return photo;
    }

    private void awaitPrefsFlush() {
        awaitFile(prefsFile());
    }

    /** SessionManager usa apply() (asíncrono): se espera a que el XML exista en disco. */
    private static void awaitFile(File f) {
        assertTrue("El archivo " + f.getName() + " no se escribió a tiempo",
                waitUntil(f::exists, 5000));
    }

    private static boolean waitUntil(BooleanSupplier condition, long timeoutMs) {
        long end = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < end) {
            try {
                if (condition.getAsBoolean()) return true;
            } catch (RuntimeException ignored) {
                // el archivo puede no existir aún
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return condition.getAsBoolean();
    }

    private static boolean isMasked(android.view.View v) {
        return ((TextView) v).getTransformationMethod() instanceof PasswordTransformationMethod;
    }

    private static void addIfNotNull(List<File> list, File f) {
        if (f != null) list.add(f);
    }

    /** Formas en las que la contraseña podría aparecer guardada: claro, Base64, SHA-256 sin salt. */
    private static List<byte[]> secretNeedles(String secret) throws Exception {
        byte[] utf8 = secret.getBytes(StandardCharsets.UTF_8);
        byte[] sha = MessageDigest.getInstance("SHA-256").digest(utf8);
        StringBuilder hex = new StringBuilder();
        for (byte b : sha) hex.append(String.format("%02x", b));
        List<byte[]> needles = new ArrayList<>();
        needles.add(utf8);
        needles.add(Base64.encode(utf8, Base64.NO_WRAP));
        needles.add(hex.toString().getBytes(StandardCharsets.UTF_8));
        needles.add(Base64.encode(sha, Base64.NO_WRAP));
        needles.add(sha);
        return needles;
    }

    private static void scanForSecrets(File dir, List<byte[]> needles, List<String> leaks)
            throws IOException {
        File[] children = dir.listFiles();
        if (children == null) return;
        for (File f : children) {
            if (f.isDirectory()) {
                scanForSecrets(f, needles, leaks);
            } else if (f.isFile() && f.length() < 50L * 1024 * 1024) {
                byte[] data = readAll(f);
                for (byte[] needle : needles) {
                    if (indexOf(data, needle) >= 0) {
                        leaks.add(f.getParentFile().getName() + "/" + f.getName());
                        break;
                    }
                }
            }
        }
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    private static byte[] readAll(File f) throws IOException {
        try (InputStream in = new FileInputStream(f)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            return out.toByteArray();
        } catch (IOException e) {
            return new byte[0]; // archivo no legible: no se puede escanear
        }
    }

    private static String readFile(File f) {
        return f.exists() ? new String(readAllQuietly(f), StandardCharsets.UTF_8) : "";
    }

    private static byte[] readAllQuietly(File f) {
        try {
            return readAll(f);
        } catch (IOException e) {
            return new byte[0];
        }
    }

    /** Vuelca logcat (una app puede leer sus propios logs) sin bloquearse. */
    private static String readLogcat() throws IOException, InterruptedException {
        Process p = new ProcessBuilder("logcat", "-d", "-v", "raw").redirectErrorStream(true).start();
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) sb.append(line).append('\n');
        }
        p.waitFor(10, TimeUnit.SECONDS);
        return sb.toString();
    }
}
