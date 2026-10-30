# Best Practices — GPSMapApp

**Paquete:** `com.example.semana9`  
Este documento distingue las medidas verificables en el código fuente de las tareas que requieren validación en un APK o dispositivo.

## Medidas presentes en el código

| Práctica | Implementación comprobable | Beneficio y alcance |
|---|---|---|
| Hash de contraseñas con salt | `DatabaseHelper.java`: `PBKDF2WithHmacSHA256`, 100.000 iteraciones, clave derivada de 256 bits y salt aleatoria de 16 bytes por usuario | Evita guardar contraseñas en texto plano. No es cifrado reversible. |
| Comparación de hash | `MessageDigest.isEqual()` | Reduce diferencias de tiempo en la comparación del hash. |
| Consultas SQL parametrizadas | `DatabaseHelper.java`: `db.query(..., selectionArgs)` y `ContentValues` | Separa los datos ingresados de la estructura SQL y reduce riesgo de inyección SQL. |
| Trabajo criptográfico fuera del hilo UI | `LoginActivity.java` y `RegisterActivity.java` utilizan `ExecutorService` | Evita bloquear la interfaz mientras se calcula PBKDF2 o se consulta SQLite. |
| Protección contra fuerza bruta | `LoginAttemptGuard.java`, `LoginService.java`, `PrefsAttemptStore.java` | Cuenta intentos antes de verificar, bloquea progresivamente y guarda el estado en preferencias privadas. La política es local y depende del reloj del dispositivo. |
| Sesión mínima y privada | `SessionManager.java`: `MODE_PRIVATE`, `user_id`, `username`, `login_at`; expiración de 7 días y `logout()` limpia preferencias | No guarda contraseña ni hash en la sesión. Las preferencias **no están cifradas**. |
| Backup deshabilitado | `AndroidManifest.xml`: `allowBackup=false`; reglas en `backup_rules.xml` y `data_extraction_rules.xml` | Reduce exposición de base de datos, preferencias y archivos mediante mecanismos de respaldo. Validar en APK final. |
| Tráfico en claro deshabilitado | `AndroidManifest.xml`: `usesCleartextTraffic=false` y `network_security_config.xml` con `cleartextTrafficPermitted=false` y certificados del sistema | Bloquea conexiones HTTP en claro. No configura certificate pinning. El proyecto no declara backend propio. |
| Clave Maps fuera del código versionado | `app/build.gradle.kts` lee `MAPS_API_KEY` desde `local.properties` o variable de entorno; `local.properties` está en `.gitignore` | Evita guardar la clave en el repositorio. No evita que una clave incorporada en el APK sea extraída; restringirla en Google Cloud. |
| Componentes internos no exportados | `AndroidManifest.xml`: `RegisterActivity` y `MainActivity` tienen `exported=false`; `LoginActivity` es el launcher exportado | Reduce la posibilidad de que otras aplicaciones invoquen pantallas internas. |
| Optimización release | `app/build.gradle.kts` activa optimización en el build type `release` | Habilita R8 para reducir/optimizar el código de release. No equivale a eliminar automáticamente todos los logs. |
| Almacenamiento privado de fotografías | `MainActivity.java` guarda fotografías bajo `getFilesDir()` | Mantiene los archivos dentro del almacenamiento privado de la aplicación. |

## Verificaciones que faltan antes de afirmar el resultado final

- Ejecutar pruebas JVM e instrumentadas y adjuntar las salidas reales.
- Analizar con MobSF el APK actualizado, no el APK histórico.
- Confirmar en el manifest fusionado la configuración de backup, red y componentes.
- Revocar la clave Maps histórica expuesta y crear una nueva restringida por paquete, SHA-1 y API.
- Firmar una versión release con un keystore propio antes de distribución.

No se afirma que exista `EncryptedSharedPreferences`, `DatabaseHelper.isValidUsername`, `InputValidator`, `proguard-rules.pro` ni certificate pinning: esos elementos no se encontraron en el código fuente revisado.
