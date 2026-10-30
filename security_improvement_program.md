# Security Improvement Program — GPSMapApp

**Paquete:** `com.example.semana9`

## 1. Objetivo

Mantener un proceso repetible para identificar, corregir y volver a evaluar riesgos de seguridad en la aplicación Android.

## 2. Ciclo de revisión

| Frecuencia / hito | Actividad | Evidencia esperada |
|---|---|---|
| Cada cambio de código | Ejecutar pruebas JVM | Salida de `./gradlew testDebugUnitTest` |
| Antes de cada entrega | Compilar APK y ejecutar análisis estático MobSF | Informe MobSF fechado y asociado al hash del APK |
| En emulador o dispositivo | Ejecutar pruebas instrumentadas y flujos principales | Salida de `./gradlew connectedDebugAndroidTest` y capturas sin datos sensibles |
| Antes de publicar | Revisar permisos, manifest fusionado, dependencias, clave Maps y firma release | Checklist firmado por el responsable |
| Trimestralmente | Revisar hallazgos abiertos, restricciones de claves y métricas | Registro de revisión y acciones actualizadas |

## 3. Métricas

| Métrica | Línea base disponible | Meta |
|---|---|---|
| MobSF histórico | 45/100 en APK debug escaneado el 27-10-2026 | Medir de nuevo sobre APK actualizado; comparar solo builds equivalentes |
| Clave Maps expuesta en artefacto histórico | Sí, visible en el PDF MobSF original | Clave histórica revocada; nueva clave restringida; ningún secreto real en repositorio o informes |
| Tráfico HTTP en claro | El reporte histórico indicaba que no había Network Security Config | `usesCleartextTraffic=false` y configuración empaquetada verificada en APK nuevo |
| Pruebas JVM | Hay suites de pruebas en `app/src/test` | Todas las pruebas pasan en cada cambio |
| Pruebas instrumentadas | Hay suites en `app/src/androidTest`; no se dispone aquí de ejecución reciente verificable | Todas ejecutadas y aprobadas en emulador/dispositivo |
| Hallazgos de alta severidad | MobSF histórico reportó hallazgos en APK debug | 0 hallazgos altos abiertos en build release, o excepción justificada |

## 4. Plan de acción

| Acción | Prioridad | Responsable sugerido | Plazo | Criterio de cierre |
|---|---|---|---|---|
| Revocar/rotar la clave Maps expuesta y restringir la nueva | Crítica | Propietario de Google Cloud / equipo | Inmediato | Clave anterior revocada y nueva restringida por paquete, SHA-1 y API |
| Compilar APK actualizado y volver a escanear con MobSF | Alta | Desarrollo | Antes de entregar/publicar | Informe nuevo sin clave antigua; configuración de red y backup confirmadas |
| Ejecutar pruebas JVM | Alta | Desarrollo | Antes de entregar | Salida completa de Gradle sin fallos |
| Ejecutar pruebas instrumentadas en emulador | Alta | Desarrollo | Antes de entregar | Salida completa de Gradle y capturas de flujos principales |
| Revisar manifest fusionado y receiver AndroidX | Media | Desarrollo | Próxima iteración | Componentes exportados justificados y documentados |
| Generar release firmado con keystore propio | Alta | Propietario del proyecto | Antes de distribución | APK/AAB release firmado y MobSF revisado |
| Evaluar cifrado de sesión con Android Keystore | Baja | Desarrollo | Backlog | Decisión técnica documentada y pruebas actualizadas si se implementa |
| Evaluar límites anti-fuerza-bruta del lado servidor si se incorpora backend | Media | Desarrollo | Al incorporar backend | Pruebas de password spraying y límites centralizados |

## 5. Responsabilidades y control

El responsable de cada acción debe adjuntar evidencia reproducible, registrar fecha y versión del APK y actualizar `vulnerabilities.md`. Las tareas no verificadas deben permanecer como pendientes; no se deben marcar como implementadas solo por estar planificadas.
