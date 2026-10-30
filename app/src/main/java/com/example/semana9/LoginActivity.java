package com.example.semana9;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.google.android.material.textfield.TextInputEditText;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Pantalla de inicio de sesión (es la pantalla inicial de la app). */
public class LoginActivity extends AppCompatActivity {

    private TextInputEditText etUsername;
    private TextInputEditText etPassword;
    private Button btnLogin;

    private DatabaseHelper db;
    private LoginService loginService;
    private SessionManager session;
    // El hash PBKDF2 es costoso a propósito, así que se calcula fuera del hilo principal.
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        session = new SessionManager(this);
        if (session.isLoggedIn()) {
            goToMain();
            return;
        }

        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_login);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.loginRoot), (v, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return insets;
        });

        db = new DatabaseHelper(this);
        loginService = LoginService.create(this, db);
        etUsername = findViewById(R.id.etUsername);
        etPassword = findViewById(R.id.etPassword);
        btnLogin = findViewById(R.id.btnLogin);
        TextView tvGoRegister = findViewById(R.id.tvGoRegister);

        btnLogin.setOnClickListener(v -> attemptLogin());
        tvGoRegister.setOnClickListener(v ->
                startActivity(new Intent(this, RegisterActivity.class)));
    }

    private void attemptLogin() {
        String username = text(etUsername);
        String password = raw(etPassword);

        if (username.isEmpty() || password.isEmpty()) {
            Toast.makeText(this, R.string.fill_all_fields, Toast.LENGTH_SHORT).show();
            return;
        }

        // Bloqueo anti fuerza bruta: si el usuario está bloqueado ni siquiera se intenta.
        long lockedFor = loginService.remainingLockMs(username);
        if (lockedFor > 0) {
            showLocked(lockedFor);
            return;
        }

        btnLogin.setEnabled(false);
        executor.execute(() -> {
            long userId = loginService.login(username, password);
            long lockedAfter = userId < 0 ? loginService.remainingLockMs(username) : 0;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) {
                    return;
                }
                if (userId > 0) { // ids válidos >= 1; -1 = inválido, -2 = bloqueado
                    session.saveSession(userId, username);
                    goToMain();
                } else {
                    btnLogin.setEnabled(true);
                    if (lockedAfter > 0) {
                        showLocked(lockedAfter);
                    } else {
                        Toast.makeText(this, R.string.invalid_credentials, Toast.LENGTH_SHORT).show();
                    }
                }
            });
        });
    }

    private void showLocked(long remainingMs) {
        long seconds = (remainingMs + 999) / 1000;
        Toast.makeText(this, getString(R.string.too_many_attempts, seconds), Toast.LENGTH_LONG).show();
    }

    private void goToMain() {
        Intent intent = new Intent(this, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        startActivity(intent);
        finish();
    }

    private static String raw(TextInputEditText field) {
        return field.getText() == null ? "" : field.getText().toString();
    }

    private static String text(TextInputEditText field) {
        return field.getText() == null ? "" : field.getText().toString().trim();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}
