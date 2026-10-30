package com.example.semana9;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Guarda el estado anti fuerza bruta en SharedPreferences privadas. Usa commit() (síncrono)
 * para que un intento quede contado en disco aunque se mate el proceso justo después.
 * Debe llamarse desde un hilo secundario, igual que el login.
 */
public class PrefsAttemptStore implements AttemptStore {

    static final String PREFS = "login_guard";

    private final SharedPreferences prefs;

    public PrefsAttemptStore(Context context) {
        prefs = context.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    @Override
    public State load(String key) {
        State s = new State();
        s.failures = prefs.getInt(key + ".f", 0);
        s.lockUntil = prefs.getLong(key + ".l", 0);
        return s;
    }

    @Override
    public void save(String key, State s) {
        prefs.edit().putInt(key + ".f", s.failures).putLong(key + ".l", s.lockUntil).commit();
    }

    @Override
    public void clear(String key) {
        prefs.edit().remove(key + ".f").remove(key + ".l").commit();
    }
}
