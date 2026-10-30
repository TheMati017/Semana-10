package com.example.semana9;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.concurrent.TimeUnit;

/**
 * Guarda quién tiene la sesión abierta, para no pedir login cada vez que se abre la app.
 * La sesión caduca a los {@link #SESSION_MAX_AGE_DAYS} días: pasado ese tiempo hay que volver
 * a iniciar sesión (limita el daño si el dispositivo se pierde o se comparte).
 */
public class SessionManager {

    static final long SESSION_MAX_AGE_DAYS = 7;
    private static final long SESSION_MAX_AGE_MS = TimeUnit.DAYS.toMillis(SESSION_MAX_AGE_DAYS);

    private static final String PREFS = "session";
    private static final String KEY_USER_ID = "user_id";
    private static final String KEY_USERNAME = "username";
    private static final String KEY_LOGIN_AT = "login_at";

    private final SharedPreferences prefs;

    public SessionManager(Context context) {
        prefs = context.getApplicationContext()
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public void saveSession(long userId, String username) {
        prefs.edit()
                .putLong(KEY_USER_ID, userId)
                .putString(KEY_USERNAME, username)
                .putLong(KEY_LOGIN_AT, System.currentTimeMillis())
                .apply();
    }

    public boolean isLoggedIn() {
        if (prefs.getLong(KEY_USER_ID, -1) == -1) {
            return false;
        }
        long loginAt = prefs.getLong(KEY_LOGIN_AT, 0);
        long age = System.currentTimeMillis() - loginAt;
        // Sin fecha (sesión antigua), con fecha futura (reloj manipulado) o vencida: se cierra.
        if (loginAt <= 0 || age < 0 || age > SESSION_MAX_AGE_MS) {
            logout();
            return false;
        }
        return true;
    }

    public String getUsername() {
        return prefs.getString(KEY_USERNAME, "");
    }

    public void logout() {
        prefs.edit().clear().apply();
    }
}
