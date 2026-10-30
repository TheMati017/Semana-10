package com.example.semana9;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.xml.parsers.DocumentBuilderFactory;

/**
 * Pruebas de fuga de datos por análisis estático (corren en el PC, sin emulador):
 * revisan el código fuente, el manifest y los recursos buscando formas de que datos
 * sensibles (contraseñas, sesión, claves de API, fotos) salgan de la app.
 *
 * Ejecutar con:  ./gradlew testDebugUnitTest
 */
public class DataLeakStaticTest {

    private static final String ANDROID_NS = "http://schemas.android.com/apk/res/android";
    private static final Set<String> SENSITIVE_BACKUP_DOMAINS =
            new HashSet<>(Arrays.asList("database", "sharedpref", "file"));

    // ------------------------------------------------------------------ 1. Backup

    /** Con allowBackup activo, la BD (hashes) y la sesión viajarían a la nube / adb backup. */
    @Test
    public void backup_noExponeBaseDeDatosNiSesion() throws Exception {
        Element app = (Element) parseXml(manifest()).getElementsByTagName("application").item(0);
        String allowBackup = app.getAttributeNS(ANDROID_NS, "allowBackup");

        if ("false".equals(allowBackup)) {
            return; // nada se respalda: OK
        }

        // allowBackup activo (o por defecto = true): las reglas deben excluir lo sensible.
        // minSdk 30 => aplica fullBackupContent (API 30) y dataExtractionRules (API 31+).
        List<String> problemas = new ArrayList<>();

        File fullBackup = xmlResource(app.getAttributeNS(ANDROID_NS, "fullBackupContent"));
        if (fullBackup == null) {
            problemas.add("falta android:fullBackupContent (API 30 respalda todo por defecto)");
        } else {
            problemas.addAll(checkRules(parseXml(fullBackup).getDocumentElement(),
                    "fullBackupContent"));
        }

        File extraction = xmlResource(app.getAttributeNS(ANDROID_NS, "dataExtractionRules"));
        if (extraction == null) {
            problemas.add("falta android:dataExtractionRules (API 31+ respalda todo por defecto)");
        } else {
            Element root = parseXml(extraction).getDocumentElement();
            for (String section : new String[]{"cloud-backup", "device-transfer"}) {
                NodeList n = root.getElementsByTagName(section);
                if (n.getLength() == 0) {
                    problemas.add("dataExtractionRules sin <" + section + ">: se respalda todo");
                } else {
                    problemas.addAll(checkRules((Element) n.item(0), section));
                }
            }
        }
        assertTrue("android:allowBackup está activo y las reglas no protegen datos sensibles: "
                + problemas, problemas.isEmpty());
    }

    /** Un bloque de reglas es seguro si excluye los dominios sensibles (o solo incluye otros). */
    private static List<String> checkRules(Element block, String name) {
        List<String> problemas = new ArrayList<>();
        Set<String> excluded = new HashSet<>();
        Set<String> included = new HashSet<>();
        boolean hasInclude = false;
        for (Node n = block.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (!(n instanceof Element)) continue;
            Element e = (Element) n;
            if ("exclude".equals(e.getTagName())) {
                excluded.add(e.getAttribute("domain"));
            } else if ("include".equals(e.getTagName())) {
                hasInclude = true;
                included.add(e.getAttribute("domain"));
            }
        }
        for (String domain : SENSITIVE_BACKUP_DOMAINS) {
            boolean safe = hasInclude ? !included.contains(domain) : excluded.contains(domain);
            if (!safe) {
                problemas.add(name + " no protege el dominio '" + domain + "'");
            }
        }
        return problemas;
    }

    // ------------------------------------------------------------ 2. Secretos en el repo

    /**
     * Una clave de API commiteada acaba en GitHub, en el APK y en cualquier fork.
     * (La clave de Google Maps debe restringirse por package+SHA-1 y cargarse desde
     * local.properties / secrets, no versionarse.)
     */
    @Test
    public void repo_noContieneClavesDeApiNiSecretos() throws IOException {
        Pattern[] patrones = {
                Pattern.compile("AIza[0-9A-Za-z_\\-]{35}"),                       // Google API key
                Pattern.compile("AKIA[0-9A-Z]{16}"),                              // AWS access key
                Pattern.compile("-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
                Pattern.compile("xox[baprs]-[0-9A-Za-z-]{10,}"),                  // Slack token
                Pattern.compile("gh[pousr]_[0-9A-Za-z]{36,}"),                    // GitHub token
        };
        List<String> hallazgos = new ArrayList<>();
        for (Path file : textFilesOfProject()) {
            String content = readString(file);
            for (Pattern p : patrones) {
                Matcher m = p.matcher(content);
                while (m.find()) {
                    // Se enmascara el valor para no volver a filtrarlo en el reporte del test.
                    hallazgos.add(projectRoot().toPath().relativize(file) + " -> "
                            + m.group().substring(0, 6) + "…(enmascarado)");
                }
            }
        }
        assertTrue("Secretos versionados en el proyecto (rota la clave y sácala del repo): "
                + hallazgos, hallazgos.isEmpty());
    }

    @Test
    public void repo_noVersionaArchivosSecretos() throws IOException {
        Set<String> sospechosos = new HashSet<>(Arrays.asList(
                "google-services.json", ".env", "keystore.properties", "secrets.properties",
                "local.properties", "id_rsa"));
        List<String> encontrados = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(projectRoot().toPath())) {
            for (Path p : (Iterable<Path>) walk.filter(Files::isRegularFile)::iterator) {
                String name = p.getFileName().toString();
                if (isIgnoredDir(p)) continue;
                if (sospechosos.contains(name) || name.endsWith(".jks")
                        || name.endsWith(".keystore") || name.endsWith(".pem")) {
                    encontrados.add(projectRoot().toPath().relativize(p).toString());
                }
            }
        }
        assertTrue("Archivos secretos dentro del proyecto: " + encontrados, encontrados.isEmpty());

        String gitignore = readString(new File(projectRoot(), ".gitignore").toPath());
        assertTrue(".gitignore debe ignorar local.properties", gitignore.contains("local.properties"));
    }

    // ------------------------------------------------------------------ 3. Logs

    /** Logcat es legible con adb y por otras herramientas: nunca debe contener credenciales. */
    @Test
    public void codigo_noImprimeDatosSensiblesEnLogs() throws IOException {
        Pattern sink = Pattern.compile("Log\\.[vdiwe]\\(|Log\\.wtf\\(|System\\.(out|err)\\.|Timber\\.");
        Pattern secreto = Pattern.compile("(?i)\\b(password|passwd|pwd|hash|salt|token|secret)\\b|etPassword|etConfirm");
        List<String> hallazgos = new ArrayList<>();
        for (Path file : javaMain()) {
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            for (int i = 0; i < lines.size(); i++) {
                String l = lines.get(i);
                if (sink.matcher(l).find() && secreto.matcher(l).find()) {
                    hallazgos.add(file.getFileName() + ":" + (i + 1) + " " + l.trim());
                }
            }
        }
        assertTrue("Posible fuga de secretos en logs: " + hallazgos, hallazgos.isEmpty());
    }

    /** printStackTrace con datos de usuario en la excepción también termina en logcat. */
    @Test
    public void codigo_noUsaPrintStackTraceSobreFlujosDeAutenticacion() throws IOException {
        List<String> hallazgos = new ArrayList<>();
        for (Path file : javaMain()) {
            String name = file.getFileName().toString();
            if (name.equals("DatabaseHelper.java") || name.equals("LoginActivity.java")
                    || name.equals("RegisterActivity.java") || name.equals("SessionManager.java")) {
                if (readString(file).contains("printStackTrace")) {
                    hallazgos.add(name);
                }
            }
        }
        assertTrue("printStackTrace en flujos de autenticación: " + hallazgos, hallazgos.isEmpty());
    }

    // --------------------------------------------------------- 4. Almacenamiento inseguro

    /** Los datos (fotos, etc.) deben quedarse en el almacenamiento interno privado. */
    @Test
    public void codigo_noEscribeEnAlmacenamientoCompartido() throws IOException {
        Pattern inseguro = Pattern.compile(
                "MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|getExternalStorage|getExternalFilesDir"
                        + "|getExternalCacheDir|getExternalMediaDirs|DIRECTORY_(PICTURES|DCIM|DOWNLOADS)"
                        + "|MediaStore\\.Images|getExternalStoragePublicDirectory");
        List<String> hallazgos = new ArrayList<>();
        for (Path file : javaMain()) {
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            for (int i = 0; i < lines.size(); i++) {
                if (inseguro.matcher(lines.get(i)).find()) {
                    hallazgos.add(file.getFileName() + ":" + (i + 1) + " " + lines.get(i).trim());
                }
            }
        }
        assertTrue("Escritura en almacenamiento legible por otras apps: " + hallazgos,
                hallazgos.isEmpty());
    }

    @Test
    public void fotos_seGuardanEnAlmacenamientoInternoPrivado() throws IOException {
        String main = readString(mainJava("MainActivity.java"));
        assertTrue("Las fotos deben guardarse en getFilesDir() (privado de la app)",
                main.contains("new File(getFilesDir()"));
    }

    // ------------------------------------------------------------- 5. Sesión y credenciales

    /** SessionManager solo puede persistir una lista blanca de claves (id y nombre de usuario). */
    @Test
    public void sesion_soloPersisteClavesPermitidas() throws IOException {
        String src = readString(mainJava("SessionManager.java"));
        Matcher m = Pattern.compile("KEY_[A-Z_]+\\s*=\\s*\"([^\"]*)\"").matcher(src);
        Set<String> claves = new HashSet<>();
        while (m.find()) {
            claves.add(m.group(1));
        }
        Set<String> permitidas = new HashSet<>(Arrays.asList("user_id", "username", "login_at"));
        assertFalse("SessionManager no declara claves", claves.isEmpty());
        Set<String> extra = new HashSet<>(claves);
        extra.removeAll(permitidas);
        assertTrue("SessionManager guarda claves no permitidas (¿contraseña/hash/token?): " + extra,
                extra.isEmpty());
        assertTrue("Las preferencias de sesión deben ser MODE_PRIVATE",
                src.contains("Context.MODE_PRIVATE"));
    }

    /** Pasar la contraseña por Intents/Bundles la expone a otras apps y al historial de tareas. */
    @Test
    public void codigo_noPasaContrasenasPorIntentsNiBundles() throws IOException {
        Pattern sink = Pattern.compile("putExtra\\(|putString\\(|putCharSequence\\(|setData\\(");
        Pattern secreto = Pattern.compile("(?i)password|passwd|pwd|etPassword|etConfirm|raw\\(");
        List<String> hallazgos = new ArrayList<>();
        for (Path file : javaMain()) {
            if (file.getFileName().toString().equals("SessionManager.java")) continue; // prefs: otra prueba
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            for (int i = 0; i < lines.size(); i++) {
                String l = lines.get(i);
                if (sink.matcher(l).find() && secreto.matcher(l).find()) {
                    hallazgos.add(file.getFileName() + ":" + (i + 1) + " " + l.trim());
                }
            }
        }
        assertTrue("Contraseña enviada en Intent/Bundle: " + hallazgos, hallazgos.isEmpty());
    }

    /** Las contraseñas solo pueden guardarse como hash con salt, nunca con SHA/MD5 sin salt. */
    @Test
    public void contrasenas_seGuardanConKdfYSalt() throws IOException {
        String db = readString(mainJava("DatabaseHelper.java"));
        assertTrue("Debe usarse PBKDF2 (u otro KDF lento)", db.contains("PBKDF2"));
        assertTrue("Debe usarse una salt aleatoria", db.contains("SecureRandom"));
        assertFalse("MD5 no es aceptable para contraseñas", db.contains("\"MD5\""));
        assertFalse("SHA-1/SHA-256 simples no son aceptables para contraseñas",
                Pattern.compile("MessageDigest\\.getInstance\\(").matcher(db).find());
        assertFalse("No debe existir una columna de contraseña en texto plano",
                Pattern.compile("(?i)COL_PASSWORD\\s*=|\"password\"\\s*[,)]").matcher(db).find());

        Matcher it = Pattern.compile("PBKDF2_ITERATIONS\\s*=\\s*([0-9_]+)").matcher(db);
        assertTrue("No se encontró PBKDF2_ITERATIONS", it.find());
        int iterations = Integer.parseInt(it.group(1).replace("_", ""));
        assertTrue("Iteraciones PBKDF2 demasiado bajas (" + iterations + "), mínimo 100000",
                iterations >= 100_000);
    }

    /** Todas las consultas deben ir parametrizadas: nada de concatenar entrada del usuario. */
    @Test
    public void sql_noConcatenaEntradaDelUsuario() throws IOException {
        Pattern riesgo = Pattern.compile("(rawQuery|execSQL)\\s*\\([^;]*\\+\\s*(username|password|user|name|input)");
        List<String> hallazgos = new ArrayList<>();
        for (Path file : javaMain()) {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                if (riesgo.matcher(line).find()) hallazgos.add(file.getFileName() + ": " + line.trim());
            }
        }
        assertTrue("Posible inyección SQL (usa selectionArgs / ?): " + hallazgos, hallazgos.isEmpty());
    }

    // ------------------------------------------------------------- 6. Manifest y UI

    /** Solo la pantalla de login (launcher) puede ser invocada desde fuera de la app. */
    @Test
    public void manifest_soloElLauncherEstaExportado() throws Exception {
        Document doc = parseXml(manifest());
        Element app = (Element) doc.getElementsByTagName("application").item(0);
        List<String> exportados = new ArrayList<>();
        for (String tag : new String[]{"activity", "activity-alias", "service", "receiver", "provider"}) {
            NodeList list = app.getElementsByTagName(tag);
            for (int i = 0; i < list.getLength(); i++) {
                Element e = (Element) list.item(i);
                boolean exported = "true".equals(e.getAttributeNS(ANDROID_NS, "exported"));
                boolean launcher = e.getElementsByTagName("category").getLength() > 0
                        && containsLauncher(e);
                if (exported && !launcher) {
                    exportados.add(tag + " " + e.getAttributeNS(ANDROID_NS, "name"));
                }
            }
        }
        assertTrue("Componentes exportados que no son el launcher: " + exportados,
                exportados.isEmpty());
    }

    @Test
    public void manifest_sinTraficoClaroNiDebuggable() throws Exception {
        Element app = (Element) parseXml(manifest()).getElementsByTagName("application").item(0);
        assertFalse("usesCleartextTraffic=true permite HTTP sin cifrar",
                "true".equals(app.getAttributeNS(ANDROID_NS, "usesCleartextTraffic")));
        assertFalse("android:debuggable=true permite leer datos con run-as",
                "true".equals(app.getAttributeNS(ANDROID_NS, "debuggable")));
    }

    /** Las contraseñas deben ocultarse en pantalla y no aparecer en el teclado/autocompletado. */
    @Test
    public void layouts_camposDeContrasenaEnmascarados() throws Exception {
        File layouts = new File(moduleDir(), "src/main/res/layout");
        List<String> hallazgos = new ArrayList<>();
        int revisados = 0;
        File[] files = layouts.listFiles((d, n) -> n.endsWith(".xml"));
        assertTrue("No se encontraron layouts", files != null && files.length > 0);
        for (File f : files) {
            NodeList all = parseXml(f).getElementsByTagName("*");
            for (int i = 0; i < all.getLength(); i++) {
                Element e = (Element) all.item(i);
                String id = e.getAttributeNS(ANDROID_NS, "id").toLowerCase();
                if (id.contains("password")) {
                    revisados++;
                    String type = e.getAttributeNS(ANDROID_NS, "inputType");
                    if (!type.contains("textPassword") && !type.contains("numberPassword")
                            && !type.contains("textWebPassword")) {
                        hallazgos.add(f.getName() + " " + id + " inputType='" + type + "'");
                    }
                }
            }
        }
        assertTrue("No se encontró ningún campo de contraseña", revisados > 0);
        assertTrue("Campos de contraseña sin enmascarar: " + hallazgos, hallazgos.isEmpty());
    }

    /** Cerrar sesión debe borrar todas las preferencias de sesión, no solo un flag. */
    @Test
    public void logout_limpiaTodaLaSesion() throws IOException {
        String src = readString(mainJava("SessionManager.java"));
        Matcher m = Pattern.compile("void\\s+logout\\s*\\(\\)\\s*\\{([^}]*)\\}").matcher(src);
        assertTrue("No se encontró logout()", m.find());
        assertTrue("logout() debe usar clear()", m.group(1).contains(".clear()"));
    }


    // ------------------------------------------------------ 7. Medidas de endurecimiento

    /** La clave de Maps debe llegar al manifest por un placeholder, no estar escrita en recursos. */
    @Test
    public void mapsKey_seInyectaDesdeLocalPropertiesNoDesdeRecursos() throws IOException {
        String manifest = readString(manifest().toPath());
        assertTrue("El manifest debe usar ${MAPS_API_KEY}", manifest.contains("${MAPS_API_KEY}"));
        assertFalse("No debe seguir existiendo google_maps_api.xml con la clave",
                new File(moduleDir(), "src/main/res/values/google_maps_api.xml").exists());
        String gradle = readString(new File(moduleDir(), "build.gradle.kts").toPath());
        assertTrue("build.gradle.kts debe leer local.properties", gradle.contains("local.properties"));
        assertTrue("build.gradle.kts debe definir el placeholder",
                gradle.contains("manifestPlaceholders[\"MAPS_API_KEY\"]"));
        assertTrue("Falta local.properties.example para documentar la clave",
                new File(projectRoot(), "local.properties.example").exists());
    }

    /** Si el usuario no existe también se calcula un PBKDF2: mismo tiempo, no se puede enumerar. */
    @Test
    public void login_igualaTiemposParaUsuarioInexistente() throws IOException {
        String db = readString(mainJava("DatabaseHelper.java"));
        assertTrue("Falta la salt ficticia", db.contains("DUMMY_SALT"));
        assertTrue("login() debe hashear con la salt ficticia cuando el usuario no existe",
                Pattern.compile("!c\\.moveToFirst\\(\\)\\)\\s*\\{\\s*hashPassword\\([^)]*DUMMY_SALT")
                        .matcher(db).find());
    }

    @Test
    public void sesion_tieneCaducidad() throws IOException {
        String src = readString(mainJava("SessionManager.java"));
        assertTrue("La sesión debe guardar la fecha de inicio", src.contains("KEY_LOGIN_AT"));
        Matcher m = Pattern.compile("SESSION_MAX_AGE_DAYS\\s*=\\s*(\\d+)").matcher(src);
        assertTrue("Falta SESSION_MAX_AGE_DAYS", m.find());
        int days = Integer.parseInt(m.group(1));
        assertTrue("Caducidad de sesión fuera de rango razonable (1-30 días): " + days,
                days >= 1 && days <= 30);
        assertTrue("isLoggedIn() debe cerrar la sesión vencida", src.contains("logout();"));
    }

    @Test
    public void release_tieneOptimizacionYOfuscacionActivada() throws IOException {
        String gradle = readString(new File(moduleDir(), "build.gradle.kts").toPath());
        assertTrue("El build release debe tener optimization.enable = true",
                Pattern.compile("release\\s*\\{[^}]*optimization\\s*\\{[^}]*enable\\s*=\\s*true",
                        Pattern.DOTALL).matcher(gradle).find());
    }


    // ------------------------------------------------------ 8. Fuerza bruta (estático)

    /** LoginActivity no puede llamar a DatabaseHelper.login() directamente: se saltaría el bloqueo. */
    @Test
    public void fuerzaBruta_loginActivityPasaSiemprePorElServicioConBloqueo() throws IOException {
        String src = readString(mainJava("LoginActivity.java"));
        assertFalse("LoginActivity llama a db.login() y se salta el bloqueo anti fuerza bruta",
                Pattern.compile("\\bdb\\s*\\.\\s*login\\s*\\(").matcher(src).find());
        assertTrue("LoginActivity debe usar LoginService.login()", src.contains("loginService.login("));
        assertTrue("LoginActivity debe consultar el bloqueo antes de intentar",
                src.contains("remainingLockMs("));
    }

    /** LOCKED vale -2: la condición de éxito "!= -1" lo trataría como login correcto. */
    @Test
    public void fuerzaBruta_elResultadoBloqueadoNuncaCuentaComoLoginCorrecto() throws IOException {
        for (Path file : javaMain()) {
            String src = readString(file);
            assertFalse(file.getFileName() + " usa 'userId != -1' y aceptaría el resultado LOCKED",
                    Pattern.compile("userId\\s*!=\\s*-1").matcher(src).find());
        }
        assertTrue("LoginActivity debe exigir userId > 0 para iniciar sesión",
                readString(mainJava("LoginActivity.java")).contains("userId > 0"));
    }

    /** Parámetros del bloqueo dentro de rangos razonables (ni inútil ni ruinoso para el usuario). */
    @Test
    public void fuerzaBruta_politicaDeBloqueoEnRangosRazonables() throws IOException {
        String src = readString(mainJava("LoginAttemptGuard.java"));
        long max = constant(src, "MAX_ATTEMPTS");
        long base = constant(src, "BASE_LOCK_MS");
        long cap = constant(src, "MAX_LOCK_MS");
        assertTrue("MAX_ATTEMPTS debe estar entre 3 y 10 (actual " + max + ")", max >= 3 && max <= 10);
        assertTrue("BASE_LOCK_MS debe ser al menos 10 s (actual " + base + ")", base >= 10_000);
        assertTrue("MAX_LOCK_MS debe ser al menos 5 min (actual " + cap + ")", cap >= 300_000);
        assertTrue("MAX_LOCK_MS no debería superar 24 h (actual " + cap + ")", cap <= 86_400_000L);
        assertTrue("MAX_LOCK_MS debe ser >= BASE_LOCK_MS", cap >= base);
    }

    /** El guard debe contar el intento ANTES de verificar (si no, el paralelismo lo burla). */
    @Test
    public void fuerzaBruta_elIntentoSeCuentaAntesDeVerificarYDeFormaAtomica() throws IOException {
        String guard = readString(mainJava("LoginAttemptGuard.java"));
        assertTrue("beginAttempt debe ser atómico (synchronized)",
                Pattern.compile("beginAttempt\\([^)]*\\)\\s*\\{\\s*synchronized").matcher(guard).find());
        String svc = readString(mainJava("LoginService.java"));
        assertTrue("LoginService debe llamar a beginAttempt antes de verify",
                svc.indexOf("beginAttempt(") >= 0 && svc.indexOf("beginAttempt(") < svc.indexOf("verifier.verify("));
    }

    /** El estado del bloqueo debe persistir (si solo viviera en memoria, reiniciar la app lo borraría). */
    @Test
    public void fuerzaBruta_elEstadoSePersisteDeFormaPrivada() throws IOException {
        String store = readString(mainJava("PrefsAttemptStore.java"));
        assertTrue(store.contains("Context.MODE_PRIVATE"));
        assertTrue("Debe usar commit() para que el intento quede en disco", store.contains(".commit()"));
        assertTrue("LoginService.create debe usar PrefsAttemptStore",
                readString(mainJava("LoginService.java")).contains("new PrefsAttemptStore("));
    }

    private static long constant(String src, String name) {
        Matcher m = Pattern.compile(name + "\\s*=\\s*([0-9_]+)L?").matcher(src);
        assertTrue("No se encontró la constante " + name, m.find());
        return Long.parseLong(m.group(1).replace("_", ""));
    }

    // ------------------------------------------------------------------ utilidades

    private static boolean containsLauncher(Element component) {
        NodeList cats = component.getElementsByTagName("category");
        for (int i = 0; i < cats.getLength(); i++) {
            if ("android.intent.category.LAUNCHER".equals(
                    ((Element) cats.item(i)).getAttributeNS(ANDROID_NS, "name"))) {
                return true;
            }
        }
        return false;
    }

    /** Gradle ejecuta las pruebas con el directorio de trabajo en el módulo (app/). */
    private static File moduleDir() {
        File cwd = new File(System.getProperty("user.dir"));
        if (new File(cwd, "src/main/AndroidManifest.xml").exists()) return cwd;
        File app = new File(cwd, "app");
        if (new File(app, "src/main/AndroidManifest.xml").exists()) return app;
        fail("No se encontró el módulo app desde " + cwd);
        return cwd;
    }

    private static File projectRoot() {
        return moduleDir().getParentFile();
    }

    private static File manifest() {
        return new File(moduleDir(), "src/main/AndroidManifest.xml");
    }

    private static Path mainJava(String name) {
        return new File(moduleDir(), "src/main/java/com/example/semana9/" + name).toPath();
    }

    private static List<Path> javaMain() throws IOException {
        try (Stream<Path> s = Files.walk(new File(moduleDir(), "src/main/java").toPath())) {
            List<Path> list = s.filter(p -> p.toString().endsWith(".java")).collect(Collectors.toList());
            assertFalse("No se encontraron fuentes Java", list.isEmpty());
            return list;
        }
    }

    /** Resuelve "@xml/nombre" a src/main/res/xml/nombre.xml (null si no está declarado). */
    private static File xmlResource(String ref) {
        if (ref == null || !ref.startsWith("@xml/")) return null;
        File f = new File(moduleDir(), "src/main/res/xml/" + ref.substring(5) + ".xml");
        return f.exists() ? f : null;
    }

    private static boolean isIgnoredDir(Path p) {
        String s = p.toString().replace('\\', '/');
        return s.contains("/build/") || s.contains("/.gradle/") || s.contains("/.git/")
                || s.contains("/.idea/");
    }

    private static List<Path> textFilesOfProject() throws IOException {
        Set<String> ext = new HashSet<>(Arrays.asList("java", "kt", "kts", "xml", "properties",
                "json", "md", "txt", "toml", "gradle", "yml", "yaml"));
        try (Stream<Path> s = Files.walk(projectRoot().toPath())) {
            return s.filter(Files::isRegularFile)
                    .filter(p -> !isIgnoredDir(p))
                    .filter(p -> {
                        String n = p.getFileName().toString();
                        int dot = n.lastIndexOf('.');
                        return dot >= 0 && ext.contains(n.substring(dot + 1));
                    })
                    .collect(Collectors.toList());
        }
    }

    private static String readString(Path p) throws IOException {
        return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
    }

    private static Document parseXml(File f) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return factory.newDocumentBuilder().parse(f);
    }
}
