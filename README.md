# GPSMapApp — aplicación Android

Aplicación Android desarrollada en Java (`com.example.semana9`). Muestra Google Maps y la ubicación del usuario, permite añadir marcadores, obtener una dirección mediante geocodificación inversa y capturar/guardar fotografías en el almacenamiento interno. Incluye registro e inicio de sesión con SQLite.

## Funcionalidades

- Google Maps con ubicación actual y marcadores.
- Geocodificación inversa ejecutada fuera del hilo principal.
- Captura de fotografías y almacenamiento interno privado.
- Registro e inicio de sesión mediante SQLite.
- Contraseñas derivadas con PBKDF2-HMAC-SHA256 y salt aleatoria.
- Protección anti-fuerza-bruta con bloqueos progresivos.
- Sesión local privada con expiración de siete días.

## Tecnologías

Java, Android SDK (compileSdk 37 / minSdk 30), Google Maps SDK, Fused Location Provider, SQLite, AndroidX y Gradle Kotlin DSL.

## Configuración de Google Maps

1. Crear una clave para Maps SDK for Android en Google Cloud.
2. Restringirla por nombre de paquete `com.example.semana9`, huella SHA-1 y API Maps SDK for Android.
3. Copiar `local.properties.example` como `local.properties`.
4. Reemplazar `TU_API_KEY_AQUI` por la clave nueva en `MAPS_API_KEY`.
5. No subir `local.properties` ni incluir claves reales en capturas, informes o commits.

**Seguridad de la clave:** el informe MobSF histórico del APK anterior contenía una clave visible. Debe revocarse en Google Cloud y reemplazarse por una clave nueva restringida. La clave no puede revocarse desde el código del proyecto. Una clave usada en una app Android puede extraerse del APK, por lo que las restricciones de Google Cloud son necesarias.

## Abrir y ejecutar

1. Abrir la carpeta raíz en Android Studio.
2. Configurar `MAPS_API_KEY` como se indica arriba.
3. Esperar la sincronización de Gradle.
4. Ejecutar en un dispositivo/emulador Android con Google Play Services y permisos de ubicación habilitados.

## Pruebas

- Pruebas JVM: `./gradlew testDebugUnitTest`
- Pruebas instrumentadas: `./gradlew connectedDebugAndroidTest`

Las pruebas instrumentadas requieren un emulador o dispositivo conectado. Adjuntar la salida real de Gradle y la versión del dispositivo al informe. No considerar una prueba aprobada si solo está escrita y no se ejecutó.

## Seguridad implementada

- Consultas SQLite parametrizadas.
- Contraseñas con PBKDF2-HMAC-SHA256, salt aleatoria de 16 bytes y 100.000 iteraciones.
- Sesión mínima en SharedPreferences privadas, con expiración de siete días; la sesión no está cifrada.
- Bloqueo progresivo de intentos de login (cinco intentos y bloqueos desde 30 segundos hasta 15 minutos).
- `allowBackup=false` y reglas de exclusión de datos.
- `usesCleartextTraffic=false` y `network_security_config.xml` para impedir tráfico HTTP en claro. No se configuró certificate pinning y la app no declara backend propio.
- Clave Maps inyectada desde `local.properties` o variable de entorno, fuera del código versionado.
- Actividades internas no exportadas.

## Documentación

- [Análisis de vulnerabilidades](vulnerabilities.md)
- [Best Practices](best_practices.md)
- [Security Tips](security_tips.md)
- [Security Improvement Program](security_improvement_program.md)
- [Informe técnico de seguridad (DOCX)](Informe_Tecnico_Seguridad_GPSMapApp.docx)
- [Reporte de vulnerabilidades (PDF redactado)](vulnerability_report.pdf)

## Limitaciones conocidas

- La sesión usa SharedPreferences privadas, pero no cifradas.
- El control anti-fuerza-bruta es local y depende del reloj del dispositivo; no sustituye controles centralizados de servidor.
- La configuración de red impide HTTP en claro, pero no implementa certificate pinning.
- La clave histórica de Maps requiere revocación/rotación manual en Google Cloud.
- Se debe generar y analizar un APK nuevo después de los cambios de configuración; el reporte MobSF histórico no demuestra el estado del APK nuevo.
- [Checklist antes de entregar](CHECKLIST_ANTES_DE_ENTREGAR.md)

## Estado de verificación de este paquete

La revisión del código fuente y la actualización documental sí se realizaron. No fue posible ejecutar las pruebas Gradle en este entorno: el wrapper necesitaba descargar Gradle 9.5.0 y no había conectividad con `services.gradle.org`. Por ello, la compilación y los resultados de pruebas quedan pendientes de verificación en Android Studio.
