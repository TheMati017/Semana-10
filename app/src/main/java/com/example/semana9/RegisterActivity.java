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

/** Pantalla de registro: crea el usuario en SQLite e inicia sesión automáticamente. */
public class RegisterActivity extends AppCompatActivity {

    private static final int MIN_USERNAME = 3;
    private static final int MIN_PASSWORD = 6;

    private TextInputEditText etUsername;
    private TextInputEditText etPassword;
    private TextInputEditText etConfirm;
    private Button btnRegister;

    private DatabaseHelper db;
    private SessionManager session;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_register);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.registerRoot), (v, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return insets;
        });

        db = new DatabaseHelper(this);
        session = new SessionManager(this);

        etUsername = findViewById(R.id.etUsername);
        etPassword = findViewById(R.id.etPassword);
        etConfirm = findViewById(R.id.etConfirmPassword);
        btnRegister = findViewById(R.id.btnRegister);
        TextView tvGoLogin = findViewById(R.id.tvGoLogin);

        btnRegister.setOnClickListener(v -> attemptRegister());
        tvGoLogin.setOnClickListener(v -> finish()); // vuelve al login
    }

    private void attemptRegister() {
        String username = text(etUsername);
        String password = raw(etPassword);
        String confirm = raw(etConfirm);

        if (username.length() < MIN_USERNAME) {
            toast(R.string.username_too_short);
            return;
        }
        if (password.length() < MIN_PASSWORD) {
            toast(R.string.password_too_short);
            return;
        }
        if (!password.equals(confirm)) {
            toast(R.string.passwords_dont_match);
            return;
        }

        btnRegister.setEnabled(false);
        executor.execute(() -> {
            boolean exists = db.usernameExists(username);
            long userId = exists ? -1 : db.registerUser(username, password);
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) {
                    return;
                }
                if (exists) {
                    btnRegister.setEnabled(true);
                    toast(R.string.username_taken);
                } else if (userId == -1) {
                    btnRegister.setEnabled(true);
                    toast(R.string.register_error);
                } else {
                    session.saveSession(userId, username);
                    toast(R.string.register_success);
                    Intent intent = new Intent(this, MainActivity.class);
                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
                    startActivity(intent);
                    finish();
                }
            });
        });
    }

    private void toast(int resId) {
        Toast.makeText(this, resId, Toast.LENGTH_SHORT).show();
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
