# Security Tips — GPSMapApp

**Paquete:** `com.example.semana9`

Los siguientes consejos describen controles que sí aparecen en el código y separan las mejoras futuras de las implementaciones actuales.

## 1. Evitar inyección SQL

- **Implementación:** `DatabaseHelper.java` utiliza consultas parametrizadas con `?` y argumentos separados (`selectionArgs`). Las altas usan `ContentValues`.
- **Beneficio:** los valores del usuario se interpretan como datos y no como fragmentos SQL.
- **Pendiente:** ejecutar pruebas de inyección sobre la versión compilada y registrar los resultados. No afirmar que un conjunto de payloads fue ejecutado si no se conserva su evidencia.

## 2. No almacenar contraseñas en texto plano

- **Implementación:** `DatabaseHelper.java` deriva hashes con PBKDF2-HMAC-SHA256, 100.000 iteraciones, salt aleatoria de 16 bytes y 256 bits de salida.
- **Beneficio:** una copia de la base de datos no revela directamente las contraseñas.
- **Nota:** el número de iteraciones debe reevaluarse periódicamente según los dispositivos objetivo. La sesión no almacena la contraseña.

## 3. Minimizar y limitar la sesión

- **Implementación:** `SessionManager.java` utiliza `SharedPreferences` privadas (`MODE_PRIVATE`), guarda ID de usuario, nombre y hora de inicio, expira a los 7 días y borra todo al cerrar sesión.
- **Beneficio:** limita los datos persistidos y el tiempo de validez de la sesión.
- **Limitación:** las preferencias no están cifradas. El cifrado con Android Keystore puede evaluarse como mejora; no está implementado en esta versión.

## 4. Controlar los intentos de inicio de sesión

- **Implementación:** `LoginService` aplica `LoginAttemptGuard` antes de verificar credenciales. El control permite cinco intentos y luego aplica bloqueos progresivos desde 30 segundos hasta un máximo de 15 minutos.
- **Beneficio:** dificulta ataques automatizados contra una cuenta.
- **Limitación:** el control es local, por nombre de usuario, y usa el reloj del dispositivo. Un backend debería aplicar límites adicionales por cuenta, dispositivo, IP y comportamiento.

## 5. Deshabilitar tráfico HTTP en claro

- **Implementación agregada en esta entrega:** `AndroidManifest.xml` declara `usesCleartextTraffic=false` y referencia `@xml/network_security_config`. El archivo `network_security_config.xml` prohíbe tráfico en claro y confía en certificados del sistema.
- **Beneficio:** evita que la aplicación establezca conexiones HTTP sin cifrado.
- **Limitación:** no se configuró certificate pinning. La aplicación no declara un backend propio; no se debe aplicar pinning a dominios de Google Maps sin un diseño y mantenimiento específico.
- **Verificación pendiente:** recompilar y revisar el manifest fusionado/APK con MobSF.

## 6. Proteger la clave de Google Maps

- **Implementación:** Gradle obtiene `MAPS_API_KEY` desde `local.properties` o una variable de entorno; `local.properties` está excluido de Git.
- **Riesgo pendiente:** la clave que aparecía en el APK/reporte MobSF histórico se considera comprometida. Debe revocarse y reemplazarse desde Google Cloud Console, restringiendo la nueva clave al paquete `com.example.semana9`, su SHA-1 y Maps SDK for Android.
- **Importante:** cualquier clave usada por una app Android puede extraerse del APK; las restricciones de Google Cloud son imprescindibles.

## 7. Reducir exposición de datos y componentes

- **Implementación:** `allowBackup=false`, reglas de respaldo, almacenamiento interno para fotografías y actividades internas no exportadas.
- **Verificación pendiente:** revisar el manifest fusionado del APK nuevo y comprobar el comportamiento real de backup en un dispositivo de prueba.

## 8. Preparar una versión de distribución

- **Implementación:** el build type `release` tiene optimización activada.
- **Pendiente:** generar el APK/AAB release firmado con un keystore propio y repetir MobSF. El APK debug del informe histórico no es adecuado para producción.

## Evidencias

Registrar los comandos, fecha, dispositivo/emulador y resultados reales de:

- `./gradlew testDebugUnitTest`
- `./gradlew connectedDebugAndroidTest`
- Análisis MobSF del APK actualizado
- Pruebas de login, registro, bloqueo, cierre de sesión, mapa y cámara

No se deben incluir contraseñas, claves API, tokens ni datos personales en capturas o informes.
