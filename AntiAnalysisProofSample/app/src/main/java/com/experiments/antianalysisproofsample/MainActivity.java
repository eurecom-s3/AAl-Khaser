package com.experiments.antianalysisproofsample;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;

import com.experiments.antianalysisproofsample.checkers.environment.DebuggerDetector;
import com.experiments.antianalysisproofsample.checkers.environment.EmulatorDetector;
import com.experiments.antianalysisproofsample.checkers.environment.HookDetector;
import com.experiments.antianalysisproofsample.checkers.environment.NetworkDetector;
import com.experiments.antianalysisproofsample.checkers.environment.RootDetector;
import com.experiments.antianalysisproofsample.checkers.environment.VirtualizationDetector;
import com.experiments.antianalysisproofsample.checkers.generic.DelayedExecutor;
import com.experiments.antianalysisproofsample.checkers.generic.TimeDetector;
import com.experiments.antianalysisproofsample.checkers.tampering.FileTamperingDetector;
import com.experiments.antianalysisproofsample.checkers.tampering.GenericDetector;
import com.experiments.antianalysisproofsample.checkers.tampering.MemoryTamperingDetector;
import com.experiments.antianalysisproofsample.databinding.ActivityMainBinding;
import com.experiments.antianalysisproofsample.models.EvasiveControls;
import com.experiments.antianalysisproofsample.utils.GenericHelper;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = MainActivity.class.getCanonicalName();
    private static final int PERMISSION_REQUEST_CODE = 1;
    private static final String[] NEEDED_PERMISSIONS = {
            Manifest.permission.READ_PHONE_NUMBERS, // At least API 26 (Android Oreo)
            Manifest.permission.READ_PHONE_STATE,
            Manifest.permission.ACCESS_WIFI_STATE
    };

    private static final Object syncObject = new Object();
    private boolean isPermissionRequested = false;

    public static final Map<String, String> EVASIVE_LABELS = new HashMap<>();

    static {
        EVASIVE_LABELS.put(DebuggerDetector.class.getCanonicalName(), "Debugger Detector");
        EVASIVE_LABELS.put(EmulatorDetector.class.getCanonicalName(), "Emulator Detector");
        EVASIVE_LABELS.put(HookDetector.class.getCanonicalName(), "Hook Detector");
        EVASIVE_LABELS.put(NetworkDetector.class.getCanonicalName(), "Network Detector");
        EVASIVE_LABELS.put(RootDetector.class.getCanonicalName(), "Root Detector");
        EVASIVE_LABELS.put(VirtualizationDetector.class.getCanonicalName(), "Virtualization Detector");
        EVASIVE_LABELS.put(DebuggerDetector.class.getCanonicalName(), "Debugger Detector");
        EVASIVE_LABELS.put(DebuggerDetector.class.getCanonicalName(), "Debugger Detector");
        EVASIVE_LABELS.put(MemoryTamperingDetector.class.getCanonicalName(), "Runtime Memory Tampering Detector");
        EVASIVE_LABELS.put(GenericDetector.class.getCanonicalName(), "Generic Tampering Detector");
    }

    public static final Map<String, EvasiveControls> EVASIVE_CONTROLS = new HashMap<>();

    private void init() {
        if (EVASIVE_CONTROLS.size() > 0) {
            // init already done
            return;
        }

        Class<?> rootDetectorClass = RootDetector.class;
        try {
            EVASIVE_CONTROLS.put(rootDetectorClass.getCanonicalName(),
                    new EvasiveControls(
                            MainActivity.EVASIVE_LABELS.get(rootDetectorClass.getCanonicalName()),
                            rootDetectorClass,
                            new RootDetector(this),
                            new EvasiveControls.EvasiveMethod("is device rooted", rootDetectorClass.getDeclaredMethod("isRooted")),
                            Arrays.asList(
                                    new EvasiveControls.EvasiveMethod("Dangerous apps", rootDetectorClass.getDeclaredMethod("detectPotentiallyDangerousApps")),
                                    new EvasiveControls.EvasiveMethod("Root apps", rootDetectorClass.getDeclaredMethod("detectRootApps")),
                                    new EvasiveControls.EvasiveMethod("su user exists (Java)", rootDetectorClass.getDeclaredMethod("checkSuExists")),
                                    new EvasiveControls.EvasiveMethod("su binary exists (Java)", rootDetectorClass.getDeclaredMethod("checkForBinary", String.class), Collections.singletonList(RootDetector.BINARY_SU)),
                                    new EvasiveControls.EvasiveMethod("busybox binary exists (Java)", rootDetectorClass.getDeclaredMethod("checkForBinary", String.class), Collections.singletonList(RootDetector.BINARY_BUSYBOX)),
                                    new EvasiveControls.EvasiveMethod("Magisk binary exists (Java)", rootDetectorClass.getDeclaredMethod("checkForBinary", String.class), Collections.singletonList(RootDetector.BINARY_MAGISK)),
                                    new EvasiveControls.EvasiveMethod("Root Android Properties (Java)", rootDetectorClass.getDeclaredMethod("checkForProps")),
                                    new EvasiveControls.EvasiveMethod("Path with rw permissions (Java)", rootDetectorClass.getDeclaredMethod("checkForRWPaths")),
                                    new EvasiveControls.EvasiveMethod("Android non-release keys (Java)", rootDetectorClass.getDeclaredMethod("checkTestKeys")),
                                    new EvasiveControls.EvasiveMethod("su user exists (native)", rootDetectorClass.getDeclaredMethod("checkSuExistsNative")),
                                    new EvasiveControls.EvasiveMethod("su binary exists (native)", rootDetectorClass.getDeclaredMethod("checkForBinaryNative", String.class), Collections.singletonList(RootDetector.BINARY_SU)),
                                    new EvasiveControls.EvasiveMethod("busybox binary exists (native)", rootDetectorClass.getDeclaredMethod("checkForBinaryNative", String.class), Collections.singletonList(RootDetector.BINARY_BUSYBOX)),
                                    new EvasiveControls.EvasiveMethod("Magisk binay exists (native)", rootDetectorClass.getDeclaredMethod("checkForBinaryNative", String.class), Collections.singletonList(RootDetector.BINARY_MAGISK)),
                                    new EvasiveControls.EvasiveMethod("Root Android Properties (native)", rootDetectorClass.getDeclaredMethod("checkForPropsNative")),
                                    new EvasiveControls.EvasiveMethod("Path with rw permissions (native)", rootDetectorClass.getDeclaredMethod("checkForRWPathsNative")),
                                    new EvasiveControls.EvasiveMethod("Android non-release keys (native)", rootDetectorClass.getDeclaredMethod("checkTestKeysNative"))
                            )
                    )
            );
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }

        Class<?> debuggerDetectorClass = DebuggerDetector.class;
        try {
            EVASIVE_CONTROLS.put(debuggerDetectorClass.getCanonicalName(),
                new EvasiveControls(
                    MainActivity.EVASIVE_LABELS.get(debuggerDetectorClass.getCanonicalName()),
                    debuggerDetectorClass,
                    new DebuggerDetector(this),
                    new EvasiveControls.EvasiveMethod("is under debugger (or debug env)", debuggerDetectorClass.getDeclaredMethod("isUnderDebug")),
                    Arrays.asList(
                        new EvasiveControls.EvasiveMethod("Manifest debuggble flag", debuggerDetectorClass.getDeclaredMethod("isFlagDebuggable")),
                        new EvasiveControls.EvasiveMethod("Java debugger connected (Java)", debuggerDetectorClass.getDeclaredMethod("isDebuggerConnected")),
                        new EvasiveControls.EvasiveMethod("time check basic (Java)", debuggerDetectorClass.getDeclaredMethod("basicTimeCheck")),
                        new EvasiveControls.EvasiveMethod("Java debugger connected (native)", debuggerDetectorClass.getDeclaredMethod("detectJavaDebuggerNative")),
                        new EvasiveControls.EvasiveMethod("Default debugger TCP port open (native)", debuggerDetectorClass.getDeclaredMethod("detectDebuggerDefaultTcpPortNative")),
                        new EvasiveControls.EvasiveMethod("Detect native tracer pid (file)", debuggerDetectorClass.getDeclaredMethod("detectTracerPidNative"))
                        // new EvasiveControls.EvasiveMethod("Detect native tracer pid (ptrace)", debuggerDetectorClass.getDeclaredMethod("detectDebuggerFromPtraceNative"))
                    )
                )
            );
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }

        Class<?> emultorDetectorClazz = EmulatorDetector.class;

        // start background thread for sensor analysis
        EmulatorDetector emulatorDetector = new EmulatorDetector(this);
        emulatorDetector.startSensorThread();

        try {
            EVASIVE_CONTROLS.put(emultorDetectorClazz.getCanonicalName(),
                new EvasiveControls(
                    MainActivity.EVASIVE_LABELS.get(emultorDetectorClazz.getCanonicalName()),
                    emultorDetectorClazz,
                    emulatorDetector,
                    new EvasiveControls.EvasiveMethod("Emulator detected", emultorDetectorClazz.getDeclaredMethod("isEmulator")),
                    Arrays.asList(
                        new EvasiveControls.EvasiveMethod("Emulator Build Android Properties", emultorDetectorClazz.getDeclaredMethod("detectEmulatorBuildProps")),
                        new EvasiveControls.EvasiveMethod("Emulator adb", emultorDetectorClazz.getDeclaredMethod("detectEmulatorAdb")),
                        new EvasiveControls.EvasiveMethod("Emulated/Absent sensors (accelerometer and gyroscope)", emultorDetectorClazz.getDeclaredMethod("detectEmulatedSensors")),
                        // new EvasiveControls.EvasiveMethod("Emulated Battery", emultorDetectorClazz.getDeclaredMethod("detectEmulatedBattery")),
                        new EvasiveControls.EvasiveMethod("Emulator Android Build", emultorDetectorClazz.getDeclaredMethod("detectNotUserBuild")),
                        new EvasiveControls.EvasiveMethod("Emulated Telephony properties", emultorDetectorClazz.getDeclaredMethod("detectTelephonyProps")),
                        new EvasiveControls.EvasiveMethod("Known emulator vendor detected", emultorDetectorClazz.getDeclaredMethod("detectKnwonEmulators")),
                        // new EvasiveControls.EvasiveMethod("Qemu artifact detected", emultorDetectorClazz.getDeclaredMethod("detectQemuArtifacts")),
                        new EvasiveControls.EvasiveMethod("Qemu files detected", emultorDetectorClazz.getDeclaredMethod("hasQemuFiles")),
                        // new EvasiveControls.EvasiveMethod("Qemu brkt detected", emultorDetectorClazz.getDeclaredMethod("hasQemuBkpt")),
                        new EvasiveControls.EvasiveMethod("Qemu Android build prop detected", emultorDetectorClazz.getDeclaredMethod("hasQemuBuildProps")),
                        new EvasiveControls.EvasiveMethod("Qemu drivers detected", emultorDetectorClazz.getDeclaredMethod("hasQemuDrivers")),
                        new EvasiveControls.EvasiveMethod("Qemu tasks detected (heuristics)", emultorDetectorClazz.getDeclaredMethod("hasQemuTasks")),
                        new EvasiveControls.EvasiveMethod("Qemu CPU artifact (atomic blocks 1)", emultorDetectorClazz.getDeclaredMethod("detectQemuAtomicBasicBlockDetection")),
                        // new EvasiveControls.EvasiveMethod("Qemu SMC (atomic blocks 2)", emultorDetectorClazz.getDeclaredMethod("detectEmulatorSMC")),
                        new EvasiveControls.EvasiveMethod("Detected wrong selinux properties", emultorDetectorClazz.getDeclaredMethod("hasWrongSelinuxBuildProps")),
                        new EvasiveControls.EvasiveMethod("Wrong enforced selinux file", emultorDetectorClazz.getDeclaredMethod("detectSelinuxWrongEnforceFile"))
                    )
                )
            );
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }

        Class<?> hookDetectorClazz = HookDetector.class;
        try {
            EVASIVE_CONTROLS.put(hookDetectorClazz.getCanonicalName(),
                new EvasiveControls(
                    MainActivity.EVASIVE_LABELS.get(hookDetectorClazz.getCanonicalName()),
                    hookDetectorClazz,
                    new HookDetector(this),
                    new EvasiveControls.EvasiveMethod("is hook framework present", hookDetectorClazz.getDeclaredMethod("isHookDetected")),
                    Arrays.asList(
                        new EvasiveControls.EvasiveMethod("Detect hooking installed apps", hookDetectorClazz.getDeclaredMethod("detectHookInstalledPackageNames")),
                        new EvasiveControls.EvasiveMethod("Detect hook processes", hookDetectorClazz.getDeclaredMethod("detectHookProcessArtifacts")),
                        new EvasiveControls.EvasiveMethod("Xposed detector", hookDetectorClazz.getDeclaredMethod("customGenuineXposedDetectorNative")),
                        new EvasiveControls.EvasiveMethod("Detect Xposed hooked method ", hookDetectorClazz.getDeclaredMethod("detectXposedHookedMethodNative")),
                        new EvasiveControls.EvasiveMethod("Detect default TCP port open", hookDetectorClazz.getDeclaredMethod("isDefaultServerListening")),
                        //new EvasiveControls.EvasiveMethod("Detect Frida listening TCP port", hookDetectorClazz.getDeclaredMethod("isFridaOpenPort")),
                        new EvasiveControls.EvasiveMethod("Frida thread detected", hookDetectorClazz.getDeclaredMethod("detectFridaThreadNative")),
                        new EvasiveControls.EvasiveMethod("Frida named pipe detected", hookDetectorClazz.getDeclaredMethod("detectFridaNamedPipeNative")),
                        new EvasiveControls.EvasiveMethod("Instrumentation framework classes", hookDetectorClazz.getDeclaredMethod("detectInstrumentationFrameworkClasses"))
                    )
                )
            );
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }

        Class<?> memoryTamperingDetectorClass = MemoryTamperingDetector.class;
        try {
            EVASIVE_CONTROLS.put(memoryTamperingDetectorClass.getCanonicalName(),
                new EvasiveControls(
                    MainActivity.EVASIVE_LABELS.get(memoryTamperingDetectorClass.getCanonicalName()),
                    memoryTamperingDetectorClass,
                    new MemoryTamperingDetector(this),
                    new EvasiveControls.EvasiveMethod("is runtime memory tampered", memoryTamperingDetectorClass.getDeclaredMethod("isMemoryTampered")),
                    Arrays.asList(
                        new EvasiveControls.EvasiveMethod("Hook in stack trace (Java)", memoryTamperingDetectorClass.getDeclaredMethod("detectHookInStackTrace")),
                        new EvasiveControls.EvasiveMethod("Hook in stack trace (native)", memoryTamperingDetectorClass.getDeclaredMethod("detectHookInStackTraceNative")),
                        new EvasiveControls.EvasiveMethod("Memory to disk difference", memoryTamperingDetectorClass.getDeclaredMethod("detectRuntimeMemory2DiskDifferencesNative")),
                        new EvasiveControls.EvasiveMethod("Detect Frida string in memory", memoryTamperingDetectorClass.getDeclaredMethod("detectRuntimeMemoryFridaStringNative")),
                        new EvasiveControls.EvasiveMethod("Detect PLT hooking", memoryTamperingDetectorClass.getDeclaredMethod("detectPltHookingNative")),
                        new EvasiveControls.EvasiveMethod("Detect inline hooking", memoryTamperingDetectorClass.getDeclaredMethod("detectInlineHookingNative")),
                        new EvasiveControls.EvasiveMethod("Detect native inline breakpoint (only at the beginning of the function)", memoryTamperingDetectorClass.getDeclaredMethod("detectBreakPointNative"))
                    )
                )
            );
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }

        Class<?> networkDetectorClass = NetworkDetector.class;
        try {
            EVASIVE_CONTROLS.put(networkDetectorClass.getCanonicalName(),
                new EvasiveControls(
                    MainActivity.EVASIVE_LABELS.get(networkDetectorClass.getCanonicalName()),
                    networkDetectorClass,
                    new NetworkDetector(this),
                    new EvasiveControls.EvasiveMethod("Network artifact detected", networkDetectorClass.getDeclaredMethod("isArtifactDetected")),
                    Arrays.asList(
                        new EvasiveControls.EvasiveMethod("Detected adb over wifi", networkDetectorClass.getDeclaredMethod("detectAdbOverWifi")),
                        new EvasiveControls.EvasiveMethod("Detected VPN", networkDetectorClass.getDeclaredMethod("detectVpn")),
                        new EvasiveControls.EvasiveMethod("Detected firewall installed app", networkDetectorClass.getDeclaredMethod("detectFirewall")),
                        new EvasiveControls.EvasiveMethod("Detected eth0 interface (emulator!)", networkDetectorClass.getDeclaredMethod("detectEthInterface")),
                        new EvasiveControls.EvasiveMethod("Detected fake ip (emulator!)", networkDetectorClass.getDeclaredMethod("detectEmulatorIp")),
                        new EvasiveControls.EvasiveMethod("Detected problem ssl pinning (vs google!)", networkDetectorClass.getDeclaredMethod("detectProblemSslPinningOkHttp"))
                    )
                )
            );
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }

        Class<?> virtualizationDetectorClass = VirtualizationDetector.class;
        try {
            EVASIVE_CONTROLS.put(virtualizationDetectorClass.getCanonicalName(),
                new EvasiveControls(
                    MainActivity.EVASIVE_LABELS.get(virtualizationDetectorClass.getCanonicalName()),
                    virtualizationDetectorClass,
                    new VirtualizationDetector(this, this.getPackageName()),
                    new EvasiveControls.EvasiveMethod("is virtual environment", virtualizationDetectorClass.getDeclaredMethod("isVirtualized")),
                    Arrays.asList(
                        new EvasiveControls.EvasiveMethod("Fake component name", virtualizationDetectorClass.getDeclaredMethod("checkCurrentComponentName")),
                        new EvasiveControls.EvasiveMethod("Check app is not installed", virtualizationDetectorClass.getDeclaredMethod("checkAppIsNotIntalled")),
                        new EvasiveControls.EvasiveMethod("Detect host APK", virtualizationDetectorClass.getDeclaredMethod("checkHostAPK")),
                        new EvasiveControls.EvasiveMethod("Check process with same UID v1", virtualizationDetectorClass.getDeclaredMethod("checkMultipleProcessWithSameUid")),
                        new EvasiveControls.EvasiveMethod("Check process with same UID v2", virtualizationDetectorClass.getDeclaredMethod("checkMultipleProcessWithSameUid_2")),
                        new EvasiveControls.EvasiveMethod("Detect suspicious native libraries", virtualizationDetectorClass.getDeclaredMethod("checkSuspiciousNativeLib")),
                        new EvasiveControls.EvasiveMethod("Check permissions", virtualizationDetectorClass.getDeclaredMethod("checkUndeclaredPermissionCheck")),
                        new EvasiveControls.EvasiveMethod("Check app private directory structure", virtualizationDetectorClass.getDeclaredMethod("checkAppRuntimeDir")),
                        new EvasiveControls.EvasiveMethod("Detect proxy object (on ActivityManager)", virtualizationDetectorClass.getDeclaredMethod("detectAndroidManagerProxyObjectsNative"))
                    )
                )
            );
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }

        Class<?> genericDetectorClass = GenericDetector.class;
        try {
            EVASIVE_CONTROLS.put(genericDetectorClass.getCanonicalName(),
                new EvasiveControls(
                    MainActivity.EVASIVE_LABELS.get(genericDetectorClass.getCanonicalName()),
                    genericDetectorClass,
                    new GenericDetector(this),
                    new EvasiveControls.EvasiveMethod("is artifact detected", genericDetectorClass.getDeclaredMethod("isArtifactDetected")),
                    Arrays.asList(
                            new EvasiveControls.EvasiveMethod("Fake installer source", genericDetectorClass.getDeclaredMethod("detectFakeInstallerSource")),
                            new EvasiveControls.EvasiveMethod("SafetyNet basicIntegrity failed", genericDetectorClass.getDeclaredMethod("safetyNetBasicIntegrityFailed")),
                            new EvasiveControls.EvasiveMethod("SafetyNet CTS verification failed", genericDetectorClass.getDeclaredMethod("safetyNetCtsIntegrityFailed")),
                            new EvasiveControls.EvasiveMethod("Fake app signature from Android API", genericDetectorClass.getDeclaredMethod("detectFakeApkSignatureFromAndroidAPI")),
                            new EvasiveControls.EvasiveMethod("Fake app signature from APK", genericDetectorClass.getDeclaredMethod("detectFakeApkSignatureFromApk"))
                    )
                )
            );
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        switch (requestCode) {
            case PERMISSION_REQUEST_CODE:
                for (int i = 0; i < permissions.length; i++) {
                    Log.d(TAG, "Permission " + permissions[i] + " is " + (grantResults[0] == PackageManager.PERMISSION_GRANTED ? "" : "not ") + "granted");
                }

                synchronized (syncObject) {
                    isPermissionRequested = true;
                    syncObject.notifyAll();
                }

                return;
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ActivityMainBinding binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        init();

        Context context = this;

        (new FileTamperingDetector(this, this.getPackageName())).isFileTampered();

        // Ask for permission
        Set<String> nonGrantedPermissions = new HashSet<>();
        for (String neededPermission : NEEDED_PERMISSIONS) {
            if (ContextCompat.checkSelfPermission(this, neededPermission) ==
                    PackageManager.PERMISSION_GRANTED) {
                Log.d(TAG, "Permission " + neededPermission + " already granted!");
            } else {
                Log.d(TAG, "Asking permission " + neededPermission + "...");
                nonGrantedPermissions.add(neededPermission);
            }
        }

        Runnable r = () -> {
            if (nonGrantedPermissions.size() > 0) {
                requestPermissions(GenericHelper.convertCollectionToArray(nonGrantedPermissions), PERMISSION_REQUEST_CODE);
                Log.d(TAG, "Asking " + nonGrantedPermissions.size() + " permissions...");

                // Wait until the user do not answer
                synchronized (syncObject) {
                    while (!isPermissionRequested) {
                        try {
                            syncObject.wait();
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                    Log.d(TAG, "User answered to permission questions");
                }
            }
        };

        // Start thread for permission handler
        (new Thread(r)).start();

        LinearLayout linearLayout = (LinearLayout) findViewById(R.id.button_list);
        linearLayout.setOrientation(LinearLayout.VERTICAL);

        for (String targetClass : EVASIVE_LABELS.keySet()) {
            Button btn = new Button(this);
            btn.setText(EVASIVE_LABELS.get(targetClass));

            linearLayout.addView(btn);

            btn.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    Intent intent = new Intent(context, EvasiveControlsActivity.class);
                    Bundle bundle = new Bundle();
                    bundle.putString("target", targetClass);
                    intent.putExtras(bundle);
                    context.startActivity(intent);
                }
            });
        }

        Log.d(TAG, "Finish onCreate");
    }
}