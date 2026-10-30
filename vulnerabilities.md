# Análisis de vulnerabilidades — GPSMapApp

**Paquete:** `com.example.semana9`  
**Plataforma:** Android / Java  
**Alcance:** código fuente, manifest, SQLite, sesión local, configuración Gradle y reporte MobSF histórico incluido originalmente.

> **Alcance y limitación:** el PDF MobSF original corresponde a un APK de depuración escaneado el 27-10-2026 (45/100, riesgo medio). No representa automáticamente el estado del código actual. El PDF original contenía una clave de Google Maps visible; por seguridad se excluyó del paquete final y se sustituyó por un resumen redactado. La clave debe considerarse comprometida y revocarse/rotarse en Google Cloud. No se puede revocar desde este proyecto.

## Resumen de riesgos y estado actual

| Hallazgo / riesgo | Evidencia disponible | Estado en el código fuente entregado | Acción / limitación |
|---|---|---|---|
| Inyección SQL en autenticación | `DatabaseHelper.java` utiliza `?`, `selectionArgs` y `ContentValues`; no concatena los datos de usuario en consultas | Mitigación presente por consultas parametrizadas | Ejecutar pruebas funcionales de inyección sobre el APK final y guardar evidencia. |
| Tráfico HTTP en claro | El reporte MobSF histórico indicaba ausencia de Network Security Config | Corregido en el código fuente: `usesCleartextTraffic=false` y `network_security_config.xml` con CA del sistema | Volver a compilar y analizar el APK para verificar que la configuración quedó empaquetada. No hay backend propio y no se configuró pinning. |
| Clave de Google Maps expuesta en APK anterior / reporte | El PDF MobSF histórico incluía una clave literal | El código actual obtiene la clave desde `local.properties` o `MAPS_API_KEY`; el archivo local está ignorado por Git | La clave histórica sigue comprometida hasta que el propietario la revoque/rote y restrinja la nueva por paquete, SHA-1 y API. Una clave incluida en un APK siempre puede extraerse; las restricciones son obligatorias. |
| Copia de datos mediante backup | MobSF histórico reportó `allowBackup=true` | `AndroidManifest.xml` actual declara `allowBackup=false` y excluye datos en reglas de respaldo | Verificar en el APK nuevo con MobSF/ADB. |
| Receiver de AndroidX exportado | MobSF histórico informó `ProfileInstallReceiver` | No se debe asumir que el hallazgo está corregido sin inspeccionar el manifest fusionado del APK actual | Revisar manifest fusionado y actualizar dependencias si sigue apareciendo. |
| Credenciales en almacenamiento | `DatabaseHelper.java` guarda PBKDF2-HMAC-SHA256 + salt aleatoria de 16 bytes; 100.000 iteraciones, 256 bits | Mitigación presente en código | Las contraseñas no se cifran reversiblemente: se almacenan como hash derivado. Evaluar parámetros KDF según rendimiento/dispositivo. |
| Sesión local | `SessionManager.java` usa SharedPreferences privadas (`MODE_PRIVATE`) y guarda ID, usuario y fecha; caduca a 7 días | Almacenamiento privado y minimizado; **no cifrado** | No afirmar uso de EncryptedSharedPreferences/Keystore. Cifrado de sesión queda como mejora futura. |
| Fuerza bruta | `LoginAttemptGuard.java`, `LoginService.java` y `PrefsAttemptStore.java` | Bloqueo progresivo por nombre de usuario: 5 intentos y bloqueos desde 30 s hasta 900 s | Limitación: estado local y reloj del dispositivo; no sustituye controles del servidor ni protege contra password spraying distribuido. |
| Permisos de ubicación | Manifest declara ubicación precisa y aproximada; funcionalidad de mapa/ubicación | Necesarios para la función principal y solicitados en tiempo de ejecución | Mantener solicitud contextual y permitir uso sin precisión cuando la función lo permita. |
| Firma de depuración | MobSF histórico detectó certificado Android Debug y APK debug | No se ha aportado un APK release firmado con keystore propio | Firmar release antes de distribuir; el APK debug no es apto para producción. |

## Evidencia del análisis MobSF histórico

- Herramienta: MobSF v4.6.1 según el registro de análisis del proyecto.
- Fecha visible del escaneo: 27-10-2026.
- Archivo analizado: `app-debug.apk`.
- Paquete: `com.example.semana9`.
- Security Score informado: 45/100 (riesgo medio, grado B).
- El reporte señaló certificado de depuración, `debuggable=true`, `allowBackup=true`, receiver AndroidX exportado y una posible clave de Google Maps hardcodeada.
- El APK histórico no debe confundirse con el código fuente actual. Es necesario generar un APK nuevo después de los cambios y volver a escanearlo.

## Pruebas recomendadas para cerrar el análisis

1. `./gradlew testDebugUnitTest` — pruebas JVM.
2. `./gradlew connectedDebugAndroidTest` — pruebas instrumentadas con emulador/dispositivo.
3. Generar APK release y analizarlo con MobSF.
4. Confirmar en el APK que `allowBackup=false`, `usesCleartextTraffic=false`, que no hay clave antigua y que no se exportan componentes innecesarios.
5. Probar login/registro, ubicación, marcadores, cámara y cierre de sesión.

**No se declara aquí que las pruebas se hayan ejecutado durante la preparación de este ZIP.** Los resultados deben completarse con la salida real de Gradle, MobSF y el dispositivo utilizado.
