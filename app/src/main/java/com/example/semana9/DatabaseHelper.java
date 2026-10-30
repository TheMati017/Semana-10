package com.example.semana9;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Base64;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Base de datos SQLite local con una única tabla "users".
 * Las contraseñas NUNCA se guardan en texto plano: se guarda un hash PBKDF2 + salt aleatoria.
 */
public class DatabaseHelper extends SQLiteOpenHelper {

    private static final String DB_NAME = "semana9.db";
    private static final int DB_VERSION = 1;

    private static final String TABLE_USERS = "users";
    private static final String COL_ID = "id";
    private static final String COL_USERNAME = "username";
    private static final String COL_HASH = "password_hash";
    private static final String COL_SALT = "salt";
    private static final String COL_CREATED = "created_at";

    /**
     * Salt ficticia: cuando el usuario no existe se calcula igualmente un PBKDF2 con ella, para que
     * el login tarde lo mismo exista o no la cuenta (evita enumerar usuarios midiendo tiempos).
     */
    private static final byte[] DUMMY_SALT = new byte[16];

    private static final int PBKDF2_ITERATIONS = 100_000;
    private static final int KEY_LENGTH_BITS = 256;

    public DatabaseHelper(Context context) {
        super(context.getApplicationContext(), DB_NAME, null, DB_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE " + TABLE_USERS + " ("
                + COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
                + COL_USERNAME + " TEXT NOT NULL UNIQUE COLLATE NOCASE, "
                + COL_HASH + " TEXT NOT NULL, "
                + COL_SALT + " TEXT NOT NULL, "
                + COL_CREATED + " INTEGER NOT NULL)");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        // Versión simple: se recrea la tabla. En una app real se migrarían los datos.
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_USERS);
        onCreate(db);
    }

    // ------------------------------------------------------------------ API pública

    /** @return true si ya existe un usuario con ese nombre (sin distinguir mayúsculas). */
    public boolean usernameExists(String username) {
        SQLiteDatabase db = getReadableDatabase();
        try (Cursor c = db.query(TABLE_USERS, new String[]{COL_ID},
                COL_USERNAME + " = ?", new String[]{username}, null, null, null)) {
            return c.moveToFirst();
        }
    }

    /** Registra un usuario nuevo. @return el id del usuario, o -1 si no se pudo crear. */
    public long registerUser(String username, String password) {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        byte[] hash = hashPassword(password, salt);

        ContentValues values = new ContentValues();
        values.put(COL_USERNAME, username);
        values.put(COL_HASH, Base64.encodeToString(hash, Base64.NO_WRAP));
        values.put(COL_SALT, Base64.encodeToString(salt, Base64.NO_WRAP));
        values.put(COL_CREATED, System.currentTimeMillis());

        // insert() devuelve -1 si falla (por ejemplo, usuario duplicado por el UNIQUE).
        return getWritableDatabase().insert(TABLE_USERS, null, values);
    }

    /** Valida credenciales. @return el id del usuario si son correctas, o -1 si no. */
    public long login(String username, String password) {
        SQLiteDatabase db = getReadableDatabase();
        try (Cursor c = db.query(TABLE_USERS,
                new String[]{COL_ID, COL_HASH, COL_SALT},
                COL_USERNAME + " = ?", new String[]{username}, null, null, null)) {
            if (!c.moveToFirst()) {
                hashPassword(password, DUMMY_SALT); // iguala el tiempo de respuesta
                return -1;
            }
            long id = c.getLong(0);
            byte[] storedHash = Base64.decode(c.getString(1), Base64.NO_WRAP);
            byte[] salt = Base64.decode(c.getString(2), Base64.NO_WRAP);
            byte[] candidate = hashPassword(password, salt);
            // isEqual compara en tiempo constante (evita ataques de temporización).
            return MessageDigest.isEqual(storedHash, candidate) ? id : -1;
        }
    }

    // ------------------------------------------------------------------ Utilidades

    private static byte[] hashPassword(String password, byte[] salt) {
        try {
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt,
                    PBKDF2_ITERATIONS, KEY_LENGTH_BITS);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("No se pudo calcular el hash", e);
        }
    }
}
