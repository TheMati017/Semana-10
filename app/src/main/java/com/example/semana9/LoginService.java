package com.example.semana9;

import android.content.Context;

/**
 * Único punto de entrada para iniciar sesión: aplica el bloqueo anti fuerza bruta y delega la
 * verificación de credenciales. LoginActivity no debe llamar a DatabaseHelper.login() directamente.
 */
public class LoginService {

    /** Resultado de login(): usuario bloqueado por demasiados intentos (no se verificó nada). */
    public static final long LOCKED = -2;

    private final CredentialVerifier verifier;
    private final LoginAttemptGuard guard;

    public LoginService(CredentialVerifier verifier, LoginAttemptGuard guard) {
        this.verifier = verifier;
        this.guard = guard;
    }

    public static LoginService create(Context context, DatabaseHelper db) {
        return new LoginService(db::login,
                new LoginAttemptGuard(new PrefsAttemptStore(context), System::currentTimeMillis));
    }

    /** @return id del usuario, -1 si las credenciales son incorrectas o {@link #LOCKED}. */
    public long login(String username, String password) {
        if (guard.beginAttempt(username) > 0) {
            return LOCKED;
        }
        long id = verifier.verify(username, password);
        if (id != -1) {
            guard.recordSuccess(username);
        }
        return id;
    }

    /** @return ms de bloqueo restantes para ese usuario (0 si puede intentar). */
    public long remainingLockMs(String username) {
        return guard.remainingLockMs(username);
    }
}
