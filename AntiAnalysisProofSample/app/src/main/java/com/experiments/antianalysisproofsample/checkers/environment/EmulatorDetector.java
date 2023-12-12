package com.experiments.antianalysisproofsample.checkers.environment;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.os.BatteryManager;
import android.os.Build;
import android.telephony.TelephonyManager;
import android.util.Log;

import androidx.core.content.ContextCompat;

import com.experiments.antianalysisproofsample.models.sensor.BaseSensorListener;
import com.experiments.antianalysisproofsample.utils.BooleanHolder;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class EmulatorDetector {
    private static final String TAG = EmulatorDetector.class.getCanonicalName();

    public static final String[] KNOWN_NUMBERS = {
            "15555215554", // Default emulator phone numbers + VirusTotal
            "15555215556", "15555215558", "15555215560", "15555215562", "15555215564", "15555215566",
            "15555215568", "15555215570", "15555215572", "15555215574", "15555215576", "15555215578",
            "15555215580", "15555215582", "15555215584",
    };

    public static final String[] KNOWN_DEVICE_IDS = {
            "000000000000000", // Default emulator id
            "e21833235b6eef10", // VirusTotal id
            "012345678912345"
    };

    public static final String[] KNOWN_IMSI_IDS = {
            "310260000000000", // Default imsi id
    };

    private static final int MIN_PROPERTIES_THRESHOLD = 0x5;
    public static final Map<String, String> KNOWN_QEMU_PROPS = new HashMap<>();
    public static final Map<String, String> SELINUX_PROPS = new HashMap<>();

    public static final String[] KNOWN_QEMU_DRIVERS = {
            "goldfish"
    };

    public static final String[] KNOWN_QEMU_FILES = {
            "/init.goldfish.rc",
            "/sys/qemu_trace",
            "/system/bin/qemud",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/system/bin/qemu-props",
            "/dev/socket/qemud",
            "/dev/qemu_pipe"
    };

    public static final String[] KNOWN_EMULATOR_FILES = { // e.g., Genymotion
            "/dev/socket/genyd",
            "/dev/socket/baseband_genyd",
            "fstab.andy",
            "ueventd.andy.rc",
            "fstab.nox",
            "init.nox.rc",
            "ueventd.nox.rc",
            "ueventd.android_x86.rc",
            "x86.prop",
            "ueventd.ttVM_x86.rc",
            "init.ttVM_x86.rc",
            "fstab.ttVM_x86",
            "fstab.vbox86",
            "init.vbox86.rc",
            "ueventd.vbox86.rc"
    };

    private final Context mContext;
    private final boolean[] isSensorEmulated;
    private final boolean[] isSensorFinished;

    static {
        System.loadLibrary("emulatordetector");

        // Init KNOWN_QEMU_PROPS
        KNOWN_QEMU_PROPS.put("init.svc.qemud", null);
        KNOWN_QEMU_PROPS.put("init.svc.qemu-props", null);
        KNOWN_QEMU_PROPS.put("qemu.hw.mainkeys", null);
        KNOWN_QEMU_PROPS.put("qemu.sf.fake_camera", null);
        KNOWN_QEMU_PROPS.put("qemu.sf.lcd_density", null);
        KNOWN_QEMU_PROPS.put("ro.bootloader", "unknown");
        KNOWN_QEMU_PROPS.put("ro.bootmode", "unknown");
        KNOWN_QEMU_PROPS.put("ro.hardware", "goldfish"); // ranchu
        KNOWN_QEMU_PROPS.put("ro.kernel.android.qemud", null);
        KNOWN_QEMU_PROPS.put("ro.kernel.qemu.gles", null);
        KNOWN_QEMU_PROPS.put("ro.kernel.qemu", "1");
        KNOWN_QEMU_PROPS.put("ro.product.device", "generic");
        KNOWN_QEMU_PROPS.put("ro.product.model", "sdk");
        KNOWN_QEMU_PROPS.put("ro.product.name", "sdk");
        KNOWN_QEMU_PROPS.put("ro.serialno", null);

        // generic for strage selinux -> https://erev0s.com/blog/3-ways-detect-selinux-status-android-natively/
        SELINUX_PROPS.put("ro.build.selinux", "0");
        SELINUX_PROPS.put("ro.boot.selinux", "permissive|disabled");
    }

    public EmulatorDetector(Context mContext) {
        this.mContext = mContext;
        this.isSensorEmulated = new boolean[1];
        this.isSensorEmulated[0] = false;
        this.isSensorFinished = new boolean[1];
        this.isSensorFinished[0] = false;
    }

    // Check Android Build props
    public boolean detectEmulatorBuildProps() {
        @SuppressLint("HardwareIds") boolean result = Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("sdk")
                || Build.MODEL.toLowerCase().contains("droid4x")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains("Genymotion")
                || Build.MANUFACTURER.contains("unknown")
                || Build.HARDWARE.contains("goldfish")
                || Build.HARDWARE.contains("ranchu")
                || Build.HARDWARE.contains("ttVM_x86")
                || Build.HARDWARE.equals("vbox86")
                || Build.PRODUCT.equals("sdk")
                || Build.PRODUCT.equals("google_sdk")
                || Build.PRODUCT.equals("sdk_x86")
                || Build.PRODUCT.equals("vbox86p")
                || Build.PRODUCT.contains("google_sdk")
                || Build.PRODUCT.contains("sdk")
                || Build.BOARD.toLowerCase().contains("nox")
                || Build.BOOTLOADER.toLowerCase().contains("nox")
                || Build.HARDWARE.toLowerCase().contains("nox")
                || Build.PRODUCT.toLowerCase().contains("nox")
                || Build.SERIAL == null
                || Build.SERIAL.toLowerCase().contains("nox")
                || Build.ID.contains("FRF91")
                || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
                || Build.TAGS.contains("test-keys")
                || Build.USER.contains("android-build");

        Log.d(TAG, "* detectEmulatorBuildProps: " + result);
        return result;
    }

    // Check Telephony property
    private boolean isSupportTelePhony() {
        PackageManager packageManager = mContext.getPackageManager();
        return packageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY);
    }

    private boolean hasKnownPhoneNumber() {
        TelephonyManager telephonyManager = (TelephonyManager) mContext.getSystemService(Context.TELEPHONY_SERVICE);

        try {
            String phoneNumber = telephonyManager.getLine1Number();
            Log.d(TAG, "getLine1Number() = " + phoneNumber);
            if (phoneNumber.startsWith("+")) {
                phoneNumber = phoneNumber.substring(1);
            }
            for (String number : KNOWN_NUMBERS) {
                if (number.equalsIgnoreCase(phoneNumber)) {
                    return true;
                }

            }
        } catch( SecurityException exception) {
            Log.e(TAG, "Unable to request getLine1Number, failing open :" + exception.toString());
        }

        return false;
    }

    private boolean hasKnownDeviceId() {
        TelephonyManager telephonyManager = (TelephonyManager) mContext.getSystemService(Context.TELEPHONY_SERVICE);

        try {
            String deviceId = telephonyManager.getDeviceId();
            Log.d(TAG, "getDeviceId() = " + deviceId);
            for (String known_deviceId : KNOWN_DEVICE_IDS) {
                if (known_deviceId.equalsIgnoreCase(deviceId)) {
                    return true;
                }
            }
        } catch( SecurityException exception) {
            Log.e(TAG, "Unable to request getDeviceId, failing open :" + exception.toString());
        }

        return false;
    }

    private boolean hasKnownImsi() {
        TelephonyManager telephonyManager = (TelephonyManager) mContext.getSystemService(Context.TELEPHONY_SERVICE);

        try {
            String imsi = telephonyManager.getSubscriberId();
            Log.d(TAG, "getSubscriberId() = " + imsi);
            for (String known_imsi : KNOWN_IMSI_IDS) {
                if (known_imsi.equalsIgnoreCase(imsi)) {
                    return true;
                }
            }
        } catch( SecurityException exception) {
            Log.e(TAG, "Unable to request getSubscriberId, failing open :" + exception.toString());
        }

        return false;
    }

    private boolean hasKnownOperatorName() {
        String szOperatorName = ((TelephonyManager) mContext.getSystemService(Context.TELEPHONY_SERVICE)).getNetworkOperatorName();
        Log.d(TAG, "getNetworkOperatorName() = " + szOperatorName);
        return szOperatorName.equalsIgnoreCase("android");
    }

    // Note: We need granted permission to check the Telephony manager permissions!
    public boolean detectTelephonyProps() {
        boolean result = hasKnownOperatorName();
        hasKnownPhoneNumber();
        hasKnownDeviceId();
        hasKnownImsi();
        if (!result &&
                ContextCompat.checkSelfPermission(mContext, Manifest.permission.READ_PHONE_STATE)
                    == PackageManager.PERMISSION_GRANTED && isSupportTelePhony()) {
            result = hasKnownPhoneNumber()
                    || hasKnownDeviceId()
                    || hasKnownImsi();
        }

        Log.d(TAG, "* detectTelephonyProps: " + result);
        return result;
    }

    public boolean detectEmulatedSensors() {
        if (!this.isSensorFinished[0]) {
            Log.e(TAG, "The thread sensor is not finish yet!");
            throw new IllegalStateException("Thread sensor is not finish yet");
        }

        Log.d(TAG, "* detectEmulatedSensors: " + this.isSensorEmulated[0]);
        return this.isSensorEmulated[0];
    }

    public void startSensorThread() {
        Context context = this.mContext;
        Runnable runnable = new Runnable() {
            @Override
            public void run() {
                // Retrieve sensor lists
                List<BaseSensorListener> listeners = new ArrayList<>();
                for (String clazzListener : new String[]{"AccelerometerSensorEventListener", "GyroscopeSensorEventListener"}) {
                    Class clazz = null;
                    Constructor constructor = null;
                    try {
                        clazz = this.getClass().getClassLoader().loadClass("com.experiments.antianalysisproofsample.models.sensor." + clazzListener);
                        constructor = clazz.getConstructor(Context.class, int.class, BooleanHolder.class);

                        // Create new object
                        BooleanHolder bh = new BooleanHolder();
                        BaseSensorListener listener = (BaseSensorListener) constructor.newInstance(context, 10, bh);
                        Log.d(TAG, "Added listener " + clazzListener + " result : " + listeners.add(listener));
                    } catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException | InstantiationException | InvocationTargetException e) {
                        Log.e(TAG, "Sensor register " + clazzListener + " failed. Message : " + e.getMessage());
                        // e.printStackTrace();
                        // continue;
                    }
                }

                for (BaseSensorListener listener : listeners) {
                    BooleanHolder syncObject = listener.getSyncObject();
                    synchronized (syncObject) {
                        while (!syncObject.isTaskFinished) {
                            try {
                                syncObject.wait();
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                    isSensorEmulated[0] |= listener.isEmulator();
                    if (isSensorEmulated[0]) {
                        break;
                    }
                }

                // notify main thread
                isSensorFinished[0] = true;
            }
        };

        new Thread(runnable).start();
    }

    // NOTE: This is only one possible way to retrive propery values
    public static String getProp(String propName) {
        Process process = null;
        try {
            process = new ProcessBuilder().command("/system/bin/getprop")
                    .redirectErrorStream(true).start();
        } catch (IOException e) {
            throw new UnsupportedOperationException();
        }

        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        String value;
        try {
            while ((line = bufferedReader.readLine()) != null) {
                if (line.contains(propName)) {
                    value = line.split(":")[1].trim();
                    value = value.substring(1, value.length() - 1);
                    return value;
                }
            }
        } catch (IOException e) {
            throw new UnsupportedOperationException();
        }

        throw new UnsupportedOperationException();
    }

    public boolean hasQemuBuildProps() {
        int found_props = 0;

        for (String prop : KNOWN_QEMU_PROPS.keySet()) {
            try {
                String property_value = getProp(prop);
                if (KNOWN_QEMU_PROPS.get(prop) == null && !"".equals(property_value)) {
                    // property should not be present (null) but it has a value!
                    Log.d(TAG, "Found Qemu build props " + prop + " is null");
                    found_props++;
                }
                if (KNOWN_QEMU_PROPS.get(prop) != null && property_value.contains(KNOWN_QEMU_PROPS.get(prop))) {
                    Log.d(TAG, "Found Qemu build props " + prop + " is fake");
                    found_props++;
                }
            } catch (UnsupportedOperationException e) {
                // property is not present in the system
                /*if (KNOWN_QEMU_PROPS.get(prop) != null) {
                    // property should be present but it is not
                    found_props++;
                }*/
                continue;
            }
        }

        return found_props >= MIN_PROPERTIES_THRESHOLD;
    }

    public boolean hasWrongSelinuxBuildProps() {
        boolean result = false;

        for (String prop : SELINUX_PROPS.keySet()) {
            try {
                String property_value = getProp(prop);
                if (SELINUX_PROPS.get(prop) == null) {
                    result = true;
                    break;
                }
                if (SELINUX_PROPS.get(prop) != null) {
                    for (String wrongValue : SELINUX_PROPS.get(prop).split("\\|")) {
                        if (property_value.contains(wrongValue)) {
                            result = true;
                            break;
                        }
                    }
                }
            } catch (UnsupportedOperationException e) {
                // property is not present in the system
                continue;
            }
        }

        return result;
    }

    public native boolean detectSelinuxWrongEnforceFile();

    public boolean hasQemuDrivers() { // Contains also hasQemuCpuInfo
        for (File drivers_file : new File[]{
                new File("/proc/tty/drivers"),
                new File("/proc/cpuinfo")}) {
            if (drivers_file.exists() && drivers_file.canRead()) {
                // We don't care to read much past things since info we care about should be inside here
                byte[] data = new byte[1024];
                try {
                    InputStream is = new FileInputStream(drivers_file);
                    is.read(data);
                    is.close();
                } catch (Exception exception) {
                    exception.printStackTrace();
                }

                String driver_data = new String(data);
                for (String known_qemu_driver : KNOWN_QEMU_DRIVERS) {
                    if (driver_data.toLowerCase().contains(known_qemu_driver)) {
                        Log.d(TAG, "Detected Qemu driver " + driver_data);
                        return true;
                    }
                }
            }
        }

        return false;
    }

    public boolean hasQemuFiles() { // contains also hasQemuPipes
        for (String qemu_file : KNOWN_QEMU_FILES) {
            if (new File(qemu_file).exists()) {
                Log.d(TAG, "Qemu file " + qemu_file + " detected!");
                return true;
            }
        }
        return false;
    }

    private native String checkQemuTasksNative();

    public boolean hasQemuTasks() {
        String res = checkQemuTasksNative();
        Log.d(TAG, "checkQemuTasksNative return " + res);
        return res != null && res.contains("5000");
    }

    private native int qemuBkptNative();

    public boolean hasQemuBkpt() {
        int qemuBkpt = qemuBkptNative();
        Log.d(TAG, "qemuBkptNative return " + qemuBkpt);
        return qemuBkpt > 0;
    }

    public boolean detectQemuArtifacts() {
        boolean result = hasQemuFiles()
                // || hasQemuPipes()
                || hasQemuBkpt()
                || hasQemuBuildProps()
                || hasQemuDrivers()
                || hasQemuTasks();

        Log.d(TAG, "* detectQemuArtifacts: " + result);
        return result;
    }

    // from: https://github.com/Fuzion24/AndroidHostileEnvironmentDetection
    private native double qemuFingerPrint();

    public boolean detectQemuAtomicBasicBlockDetection() {

	/*
		A physical CPU increases the program counter after each instruction such that the
		program counter is always up to date. Since the registers in the translated code are emulated
		in order to keep the program counter up to date after each instruction, the
		translator would have to increase the virtual program counter. This would results in
		at least one additional program counter increase for each source code instruction. However
		since the translated target code is executed natively, a correct virtual program counter
		is only necessary in cases where an instruction from the source code accesses
		it. Qemu handles these cases but otherwise does not update the program counter
		in the virtual CPU register as part of an optimization. As a consequence the
		virtual program counter often just points to the start of a basic block since it
		is updated after every branch.
	*/
        double entValue = qemuFingerPrint();
        Log.d(TAG, "Qemu fingerprint: " + entValue);

        boolean result = entValue < 0.05;
        Log.d(TAG, "* detectQemuAtomicBasicBlockDetection : " + result);
        return result;
    }

    // Emulator adb
    public boolean detectEmulatorAdb() {
        boolean result;
        try {
            boolean adbInEmulator = false;
            BufferedReader reader = null;
            try {
                reader = new BufferedReader(new InputStreamReader(new FileInputStream("/proc/net/tcp")), 1000);
                String line;
                // Skip column names
                reader.readLine();

                ArrayList<List<String>> tcpList = new ArrayList<>();

                while ((line = reader.readLine()) != null) {
                    tcpList.add(Arrays.asList(line.split("\\W+")));
                }

                reader.close();

                // Adb is always bounce to 0.0.0.0 - though the port can change
                // real devices should be != 127.0.0.1
                int adbPort = -1;
                for (List<String> tcpItem : tcpList) {
                    if (Long.parseLong(tcpItem.get(2), 16) == 0) {
                        adbPort = Integer.parseInt(tcpItem.get(3), 16);
                        break;
                    }
                }

                if (adbPort != -1) {
                    for (List<String> tcpItem : tcpList) {
                        if ((Long.parseLong(tcpItem.get(2), 16) != 0) &&
                                (Integer.parseInt(tcpItem.get(3), 16) == adbPort)) {
                            adbInEmulator = true;
                        }
                    }
                }
            } catch (Exception exception) {
                exception.printStackTrace();
            } finally {
                if (reader != null) {
                    reader.close();
                }
            }

            result = adbInEmulator;
        } catch (Exception exception) {
            exception.printStackTrace();
            result = false;
        }

        Log.d(TAG, "* detectEmulatorAdb: " + result);
        return result;
    }

    // Check Android user build
    public boolean detectNotUserBuild(){
        try {
            return !getProp("ro.build.type").equals("user");
        } catch (UnsupportedOperationException e) {
            return false;
        }
    }

    // Check well-known emulator files (e.g., genymotion)
    public boolean detectKnwonEmulators() {
        for (String qemu_file : KNOWN_EMULATOR_FILES) {
            if (new File(qemu_file).exists())
                return true;
        }
        return false;
    }

    // TODO: which heristics based on battery status is the best for emulator detector?
    /*public boolean detectEmulatedBattery() {
        boolean result = false;

        BatteryManager batteryManager = this.mContext.getSystemService(BatteryManager.class);

        IntentFilter ifilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
        Intent batteryStatus = this.mContext.registerReceiver(null, ifilter);

        int chargeStatus = batteryStatus.getIntExtra(BatteryManager.EXTRA_STATUS, -1);
        boolean isCharging =
                chargeStatus == BatteryManager.BATTERY_STATUS_CHARGING ||
                chargeStatus == BatteryManager.BATTERY_STATUS_FULL;

        int chargePlug = batteryStatus.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1);
        boolean usbCharge = chargePlug == BatteryManager.BATTERY_PLUGGED_USB;
        boolean acCharge = chargePlug == BatteryManager.BATTERY_PLUGGED_AC;

        int level = batteryStatus.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
        int scale = batteryStatus.getIntExtra(BatteryManager.EXTRA_SCALE, -1);

        float batteryPct = level * 100 / (float)scale;

        Log.d(TAG, "* detectEmulatedBattery : " + result);
        return result;
    }*/

    public boolean isEmulator() {
        NetworkDetector networkDetector = new NetworkDetector(this.mContext);

        return networkDetector.isEmulatorArtifactDetected() ||
                detectEmulatorBuildProps() ||
                detectEmulatorAdb() ||
                detectEmulatedSensors() ||
                detectNotUserBuild() ||
                detectQemuArtifacts() ||
                detectTelephonyProps() ||
                detectKnwonEmulators() ||
                detectQemuAtomicBasicBlockDetection() ||
                hasWrongSelinuxBuildProps() ||
                detectSelinuxWrongEnforceFile();
    }

}
