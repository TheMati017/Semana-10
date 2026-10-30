package com.example.semana9;

/** Comprueba credenciales. @return el id del usuario si son correctas, o -1 si no. */
public interface CredentialVerifier {
    long verify(String username, String password);
}
