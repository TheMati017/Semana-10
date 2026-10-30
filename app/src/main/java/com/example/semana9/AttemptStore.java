package com.example.semana9;

/** Almacén del estado de intentos fallidos por usuario (en producción, SharedPreferences). */
public interface AttemptStore {

    /** Intentos acumulados y hasta cuándo (epoch ms) está bloqueado el usuario. */
    final class State {
        public int failures;
        public long lockUntil;
    }

    /** @return el estado guardado, o uno vacío si no hay. Nunca null. */
    State load(String key);

    void save(String key, State state);

    void clear(String key);
}
