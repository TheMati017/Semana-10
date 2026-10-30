package com.example.semana9;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.location.Address;
import android.location.Geocoder;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.fragment.app.FragmentManager;

import com.google.android.gms.location.FusedLocationProviderClient;
import com.google.android.gms.location.LocationServices;
import com.google.android.gms.location.Priority;
import com.google.android.gms.maps.CameraUpdateFactory;
import com.google.android.gms.maps.GoogleMap;
import com.google.android.gms.maps.OnMapReadyCallback;
import com.google.android.gms.maps.SupportMapFragment;
import com.google.android.gms.maps.model.LatLng;
import com.google.android.gms.maps.model.Marker;
import com.google.android.gms.maps.model.MarkerOptions;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Muestra un mapa con la ubicación actual del usuario, permite añadir marcadores
 * (pulsación larga en el mapa o botón "Marcar aquí") y capturar/mostrar una imagen.
 *
 * Las tareas lentas (geocodificación inversa y guardado de la foto) se ejecutan en un
 * hilo secundario (ExecutorService) y el resultado se publica en el hilo principal.
 */
public class MainActivity extends AppCompatActivity implements OnMapReadyCallback {

    private static final float DEFAULT_ZOOM = 15f;
    private static final LatLng CHILE_CENTER = new LatLng(-33.4489, -70.6693); // Santiago

    private GoogleMap mMap;
    private FusedLocationProviderClient fusedLocationClient;
    private ImageView photoPreview;
    private SessionManager session;

    // Hilo de trabajo para operaciones de E/S que no deben bloquear la UI.
    private final ExecutorService backgroundExecutor = Executors.newSingleThreadExecutor();

    private final ActivityResultLauncher<String[]> locationPermissionLauncher =
            registerForActivityResult(new ActivityResultContracts.RequestMultiplePermissions(),
                    this::onPermissionsResult);

    // Captura una miniatura (thumbnail) con la app de cámara; no requiere permiso CAMERA.
    private final ActivityResultLauncher<Void> takePictureLauncher =
            registerForActivityResult(new ActivityResultContracts.TakePicturePreview(),
                    this::onPictureTaken);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Protección: si no hay sesión iniciada, se vuelve al login.
        session = new SessionManager(this);
        if (!session.isLoggedIn()) {
            goToLogin();
            return;
        }

        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        photoPreview = findViewById(R.id.photoPreview);
        Button btnMyLocation = findViewById(R.id.btnMyLocation);
        Button btnAddMarker = findViewById(R.id.btnAddMarker);
        Button btnPhoto = findViewById(R.id.btnPhoto);

        fusedLocationClient = LocationServices.getFusedLocationProviderClient(this);

        FragmentManager fm = getSupportFragmentManager();
        SupportMapFragment mapFragment = (SupportMapFragment) fm.findFragmentById(R.id.mapFragment);
        if (mapFragment != null) {
            mapFragment.getMapAsync(this);
        }

        btnMyLocation.setOnClickListener(v -> moveToCurrentLocation(false));
        btnAddMarker.setOnClickListener(v -> moveToCurrentLocation(true));
        btnPhoto.setOnClickListener(v -> launchCamera());

        findViewById(R.id.btnLogout).setOnClickListener(v -> {
            session.logout();
            goToLogin();
        });
        Toast.makeText(this, getString(R.string.welcome_user, session.getUsername()),
                Toast.LENGTH_SHORT).show();
    }

    private void goToLogin() {
        Intent intent = new Intent(this, LoginActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        startActivity(intent);
        finish();
    }

    @Override
    public void onMapReady(@NonNull GoogleMap googleMap) {
        mMap = googleMap;
        mMap.getUiSettings().setZoomControlsEnabled(true);
        mMap.getUiSettings().setMyLocationButtonEnabled(false);

        // Vista inicial en Chile mientras se obtiene la ubicación real del GPS.
        mMap.moveCamera(CameraUpdateFactory.newLatLngZoom(CHILE_CENTER, 4f));

        // Pulsación larga = nuevo marcador en ese punto.
        mMap.setOnMapLongClickListener(this::addMarkerAt);

        Toast.makeText(this, R.string.long_press_hint, Toast.LENGTH_LONG).show();
        checkLocationPermission();
    }

    // ---------------------------------------------------------------- Permisos

    private boolean hasLocationPermission() {
        return ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
                == PackageManager.PERMISSION_GRANTED
                || ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION)
                == PackageManager.PERMISSION_GRANTED;
    }

    private void checkLocationPermission() {
        if (hasLocationPermission()) {
            enableMyLocationLayer();
            moveToCurrentLocation(false);
        } else {
            locationPermissionLauncher.launch(new String[]{
                    Manifest.permission.ACCESS_FINE_LOCATION,
                    Manifest.permission.ACCESS_COARSE_LOCATION});
        }
    }

    private void onPermissionsResult(Map<String, Boolean> result) {
        if (hasLocationPermission()) {
            enableMyLocationLayer();
            moveToCurrentLocation(false);
        } else {
            Toast.makeText(this, R.string.permission_denied, Toast.LENGTH_SHORT).show();
        }
    }

    @SuppressWarnings("MissingPermission")
    private void enableMyLocationLayer() {
        if (mMap != null && hasLocationPermission()) {
            mMap.setMyLocationEnabled(true); // punto azul de la ubicación actual
        }
    }

    // --------------------------------------------------------------- Ubicación

    /**
     * Obtiene la ubicación actual, centra el mapa y opcionalmente deja un marcador.
     */
    @SuppressWarnings("MissingPermission")
    private void moveToCurrentLocation(boolean addMarker) {
        if (mMap == null) {
            return;
        }
        if (!hasLocationPermission()) {
            checkLocationPermission();
            return;
        }
        fusedLocationClient.getCurrentLocation(Priority.PRIORITY_HIGH_ACCURACY, null)
                .addOnSuccessListener(this, location -> {
                    if (location == null) {
                        Toast.makeText(this, R.string.location_unavailable, Toast.LENGTH_LONG).show();
                        return;
                    }
                    LatLng here = new LatLng(location.getLatitude(), location.getLongitude());
                    mMap.animateCamera(CameraUpdateFactory.newLatLngZoom(here, DEFAULT_ZOOM));
                    if (addMarker) {
                        addMarkerAt(here);
                    }
                })
                .addOnFailureListener(this, e ->
                        Toast.makeText(this, R.string.location_unavailable, Toast.LENGTH_LONG).show());
    }

    // ---------------------------------------------------------------- Marcadores

    private void addMarkerAt(@NonNull LatLng position) {
        String title = getString(R.string.marker_default_title);
        Marker marker = mMap.addMarker(new MarkerOptions()
                .position(position)
                .title(title)
                .snippet(String.format(Locale.getDefault(), "%.5f, %.5f",
                        position.latitude, position.longitude)));
        if (marker != null) {
            resolveAddressAsync(marker, position);
        }
    }

    /**
     * La geocodificación inversa hace red/E/S, así que se hace fuera del hilo principal
     * y el título del marcador se actualiza luego con runOnUiThread.
     */
    @SuppressWarnings("deprecation")
    private void resolveAddressAsync(@NonNull Marker marker, @NonNull LatLng position) {
        backgroundExecutor.execute(() -> {
            String address = null;
            try {
                if (Geocoder.isPresent()) {
                    Geocoder geocoder = new Geocoder(this, Locale.getDefault());
                    List<Address> results =
                            geocoder.getFromLocation(position.latitude, position.longitude, 1);
                    if (results != null && !results.isEmpty()) {
                        address = results.get(0).getAddressLine(0);
                    }
                }
            } catch (IOException ignored) {
                // Sin red o servicio no disponible: se deja el marcador con coordenadas.
            }
            final String finalAddress = address;
            if (finalAddress != null) {
                runOnUiThread(() -> {
                    if (!isFinishing() && !isDestroyed()) {
                        marker.setTitle(finalAddress);
                    }
                });
            }
        });
    }

    // -------------------------------------------------------------------- Imagen

    private void launchCamera() {
        try {
            takePictureLauncher.launch(null);
        } catch (android.content.ActivityNotFoundException e) {
            Toast.makeText(this, R.string.no_camera_app, Toast.LENGTH_SHORT).show();
        }
    }

    private void onPictureTaken(@Nullable Bitmap bitmap) {
        if (bitmap == null) {
            return; // el usuario canceló
        }
        photoPreview.setImageBitmap(bitmap);
        photoPreview.setVisibility(View.VISIBLE);
        savePhotoAsync(bitmap);
    }

    /** Guarda la foto como JPEG en el almacenamiento interno, en un hilo secundario. */
    private void savePhotoAsync(@NonNull Bitmap bitmap) {
        backgroundExecutor.execute(() -> {
            File file = new File(getFilesDir(), "foto_" + System.currentTimeMillis() + ".jpg");
            boolean ok;
            try (FileOutputStream out = new FileOutputStream(file)) {
                ok = bitmap.compress(Bitmap.CompressFormat.JPEG, 90, out);
            } catch (IOException e) {
                ok = false;
            }
            final boolean saved = ok;
            runOnUiThread(() -> {
                if (!isFinishing() && !isDestroyed()) {
                    Toast.makeText(this,
                            saved ? R.string.photo_saved : R.string.photo_save_error,
                            Toast.LENGTH_SHORT).show();
                }
            });
        });
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        backgroundExecutor.shutdown();
    }
}
