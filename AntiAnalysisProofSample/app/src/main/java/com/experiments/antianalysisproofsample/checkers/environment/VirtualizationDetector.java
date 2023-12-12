package com.experiments.antianalysisproofsample.checkers.environment;

import android.annotation.SuppressLint;
import android.app.ActivityManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PermissionGroupInfo;
import android.content.pm.PermissionInfo;
import android.os.IBinder;
import android.util.Log;

import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

public class VirtualizationDetector {
    private static final String TAG = VirtualizationDetector.class.getCanonicalName();

    private static final String[] KNOWN_LIBS = {
            "debuggerdetector",
            "emulatordetector",
            "hookdetector",
            "memorytamperigndetector",
            "rootdetector",
            "virtualizationdetector"
    };

    private final Context mContext;
    private final String packageName;

    static {
        System.loadLibrary("virtualizationdetector");
    }

    public VirtualizationDetector(Context mContext, String packageName) {
        this.mContext = mContext;
        this.packageName = packageName;
    }

    public boolean checkAppIsNotIntalled() {
        boolean result = true;

        PackageManager pm = this.mContext.getPackageManager();
        try {
            Log.d(TAG, "My package name is: " + this.packageName);
            PackageInfo packageInfo = pm.getPackageInfo(this.packageName, 0); // it is not enougth because the container app replace the package name of the plugin one!
            result = false;

            @SuppressLint("QueryPermissionsNeeded") List<ApplicationInfo> applicationInfos = pm.getInstalledApplications(PackageManager.GET_META_DATA);
            Set<String> installedPakages = new HashSet<>();
            for (ApplicationInfo applicationInfo : applicationInfos) {
                Log.d(TAG,"Installed app: " + applicationInfo.packageName);
                installedPakages.add(applicationInfo.packageName);
            }

            result = !installedPakages.contains(this.packageName);

            // Check base.apk in my private folder!
            if (!result) {
                // NOTE: alternatively check manually if /data/app/<package_name>[...]/base.apk exists

                ApplicationInfo applicationInfo;
                // Note that applicationInfos.size() == 1 is very very strange!
                if (applicationInfos.size() == 1 && (applicationInfo = applicationInfos.get(0)).packageName.equals(this.packageName)) {
                    String sourceDirPatternString = "^/data/app/([^/]+/this.packageName|this.packageName)";
                    sourceDirPatternString = sourceDirPatternString.replace("this.packageName", this.packageName);
                    Pattern sourceDirPattern = Pattern.compile(sourceDirPatternString);
                    if (!applicationInfo.sourceDir.endsWith("base.apk") || !sourceDirPattern.matcher(applicationInfo.sourceDir).find()) {
                        result = true;
                    }
                }
            }

        } catch (PackageManager.NameNotFoundException e) {
            Log.d(TAG, "NameNotFoundException exception is thrown -> under virtualization");
        }

        Log.d(TAG, "* checkAppIsNotIntalled : " + result);
        return result;
    }

    public boolean checkCurrentComponentName() {
        boolean isCorrectActivityPackage = false;
        ActivityManager manager = this.mContext.getSystemService(ActivityManager.class);
        for (ActivityManager.AppTask appTask : manager.getAppTasks()) {
            if (appTask.getTaskInfo().topActivity.toString().contains(this.packageName)) {
                isCorrectActivityPackage = true;
                break;
            }
        }

        boolean isCorrectServiceName = false;
        if (isCorrectActivityPackage) {
            // Check also services --> I need to run a different service
            // Start service
            this.mContext.startService(new Intent(this.mContext, TestService.class));
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) { /* Ignore */ }

            // Check running service names
            List<ActivityManager.RunningServiceInfo> serviceList = manager.getRunningServices(500);
            for (Iterator<ActivityManager.RunningServiceInfo> iterator = serviceList.iterator(); iterator.hasNext(); ) {
                ActivityManager.RunningServiceInfo serviceInfo = iterator.next();
                if (serviceInfo.service.toString().contains(this.packageName) || serviceInfo.service.toString().contains("VirtualizationDetector$TestService")) {
                    isCorrectServiceName = true;
                    break;
                }
            }

            // Stop service
            this.mContext.stopService(new Intent(this.mContext, TestService.class));
        }

        boolean result = !(isCorrectActivityPackage && isCorrectServiceName);
        Log.d(TAG, "* checkCurrentComponentName : " + result);
        return result;

    }

    // from: https://github.com/whucs303/DiPrint/blob/master/DiPrint/app/src/main/java/com/example/lu/diprint/DiPrint.java
    // TODO: add all check in /proc/self/maps in a common file!
    public boolean checkSuspiciousNativeLib() {
        boolean result = false;

        try {
            String encoding = "GBK";
            File file = new File("/proc/self/maps");
            if (file.isFile() && file.exists()) {
                InputStreamReader read = new InputStreamReader(
                        new FileInputStream(file), encoding);
                BufferedReader bufferedReader = new BufferedReader(read);
                String lineTxt;
                int flag = 0;
                while ((lineTxt = bufferedReader.readLine()) != null) {
                    if (lineTxt.contains(".so") &&
                            !lineTxt.contains("/system/lib") &&
                            !lineTxt.contains("/system/vendor/lib") &&
                            !lineTxt.contains("/vendor/lib") &&
                            !lineTxt.contains("/apex/") &&
                            !(lineTxt.contains("/data/data/") && lineTxt.contains(this.packageName) && lineTxt.contains("/code_cache"))) {
                        boolean isKnownLib = false;
                        for (String knownLib : KNOWN_LIBS) {
                            if (lineTxt.contains(knownLib)) {
                                isKnownLib = true;
                                break;
                            }
                        }
                        if (isKnownLib) {
                            continue;
                        }

                        Log.d(TAG, "Unknown library: " + lineTxt);
                        result = true;
                        break;
                    }
                }
                read.close();
            } else {
                System.out.println("no such file.");
            }
        } catch (Exception e) {
            System.out.println("read file error.");
            e.printStackTrace();
        }

        Log.d(TAG, "* checkSuspiciousNativeLib: " + result);
        return result;
    }

    public boolean checkHostAPK() {
        boolean result = false;
        try {
            String encoding = "GBK";
            File file = new File("/proc/self/maps");
            if (file.isFile() && file.exists()) {
                InputStreamReader read = new InputStreamReader(
                        new FileInputStream(file), encoding);
                BufferedReader bufferedReader = new BufferedReader(read);
                String lineTxt;
                while ((lineTxt = bufferedReader.readLine()) != null) {
                    if ((lineTxt.contains("base.apk") && !lineTxt.contains(this.packageName) )) {
                        result = true;
                        break;
                    }
                }
                read.close();
            } else {
                System.out.println("no such file.");
            }
        } catch (Exception e) {
            System.out.println("read file error.");
            e.printStackTrace();
        }

        Log.d(TAG, "* checkHostAPK : " + result);
        return result;
    }

    // search more processes with the same uid of the current app (i.e., the container)
    public boolean checkMultipleProcessWithSameUid() {
        boolean result = false;

        Runtime mRuntime = Runtime.getRuntime();
        String cmd = "ps";
        try {
            Process mProcess = mRuntime.exec(cmd);
            mProcess.getOutputStream().close();
            InputStream stdin = mProcess.getInputStream();
            BufferedReader br = new BufferedReader(new InputStreamReader(stdin));

            String currentLine = "";
            String findline = "";
            String uid = "null";
            while ((currentLine = br.readLine()) != null) {
                // System.out.println("process--"+currentLine);
                if (currentLine.contains(this.packageName)) {
                    uid = currentLine.split("   ")[0];
                    break;
                }
            }

            Process mProcess1 = mRuntime.exec(cmd);
            mProcess.getOutputStream().close();
            InputStream stdin1 = mProcess1.getInputStream();
            BufferedReader br1 = new BufferedReader(new InputStreamReader(stdin1));

            while ((findline = br1.readLine()) != null) {
                // System.out.println("process2--"+findline);
                // System.out.println("uid--"+uid);
                if (findline.contains(uid) &&
                        !findline.contains(this.packageName) &&
                        !findline.contains("R ps")) {
                    result = true;
                    break;
                }
            }
            br.close();
        } catch (IOException e) { /* Ignore */ }

        Log.d(TAG, "* checkMultipleProcessWithSameUid : " + result);
        return result;
    }

    // from: https://github.com/irobert-tluo/AntiPluginLib/tree/master/antipluginsdk/src
    private List<String> getDeclaredPermissions(PackageManager pm){
        List<String> perms = new ArrayList<String>();
        String pkgname = this.mContext.getApplicationContext().getPackageName();
        try {
            PackageInfo packageInfo = pm.getPackageInfo(pkgname,
                    PackageManager.GET_CONFIGURATIONS |
                            PackageManager.GET_PERMISSIONS |
                            PackageManager.GET_ACTIVITIES |
                            PackageManager.GET_SERVICES |
                            PackageManager.GET_META_DATA
            );
            if(packageInfo.permissions != null) {
                for (int i = 0; i < packageInfo.permissions.length; i++) {
                    perms.add(packageInfo.permissions[i].toString());
                }
            }
            if(packageInfo.requestedPermissions != null) {
                for (int i = 0; i < packageInfo.requestedPermissions.length; i++) {
                    perms.add(packageInfo.requestedPermissions[i].toString());
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Error To Get Declared Permissions of App");
        }
        return perms;
    }

    public boolean checkUndeclaredPermissionCheck() {
        boolean result = false;

        PackageManager pm = this.mContext.getPackageManager();

        List<String> requestedPerms = getDeclaredPermissions(pm);
        // List<String> allPerms = getAllPermissions(pm);
        Log.d(TAG, "requested permissions " + Arrays.toString(requestedPerms.toArray()));

        // NOTE: This is only a test list of non-manifest declared permissions
        List<String> knownPerms = Arrays.asList(
                "android.permission.READ_PHONE_NUMBERS",
                "android.permission.READ_PHONE_STATE",
                "android.Manifest.permission.READ_PHONE_STATE",
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.INTERNET",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.ACCESS_WIFI_STATE");

        for (String requestedPerm : requestedPerms) {
            // Check if the permission is requested from me (the plugin app) or not
            if (!knownPerms.contains(requestedPerm.trim())) {
                result = true;
                break;
            }
        }

        Log.d(TAG, "* checkUndeclaredPermissionCheck : " + result);
        return result;
    }

    @SuppressLint("SdCardPath")
    public boolean checkAppRuntimeDir() {
        boolean result = false;
        PackageManager pm = this.mContext.getPackageManager();

        try {
            ApplicationInfo ai = pm.getApplicationInfo(this.packageName, PackageManager.GET_META_DATA | PackageManager.GET_SHARED_LIBRARY_FILES);

            String dataDirPatternString = "^/data/(data|user)/([0-9]+/this.packageName|this.packageName)";
            dataDirPatternString = dataDirPatternString.replace("this.packageName", this.packageName);
            Pattern dataDirPattern = Pattern.compile(dataDirPatternString);
            result = !dataDirPattern.matcher(ai.dataDir).find();

            String sourceDirPatternString = "^/data/app/([^/]+/this.packageName|this.packageName)";
            sourceDirPatternString = sourceDirPatternString.replace("this.packageName", this.packageName);
            Pattern sourceDirPattern = Pattern.compile(sourceDirPatternString);
            result |= !sourceDirPattern.matcher(ai.sourceDir).find(); // ai.sourceDir.startsWith("/data/app/" + this.packageName);
            result |= !sourceDirPattern.matcher(ai.publicSourceDir).find(); // ai.publicSourceDir.startsWith("/data/app/" + this.packageName);

        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }

        Log.d(TAG, "* checkAppRuntimeDir : " + result);
        return result;
    }

    public boolean checkMultipleProcessWithSameUid_2() {
        boolean result = false;

        // int pid = android.os.Process.myPid();
        ActivityManager am = this.mContext.getSystemService(ActivityManager.class);
        List<ActivityManager.RunningAppProcessInfo> appProcesses = am.getRunningAppProcesses();
        if (appProcesses != null) {
            for (ActivityManager.RunningAppProcessInfo appProcess : appProcesses) {
                if (!appProcess.processName.contains(this.packageName)) {
                    result = true;
                    break;
                }
            }
        }

        Log.d(TAG, "* checkMultipleProcessWithSameUid_2 : " + result);
        return result;
    }

    public native boolean detectAndroidManagerProxyObjectsNative();

    public boolean isVirtualized() {
        return checkCurrentComponentName() ||
                checkAppIsNotIntalled() ||
                checkHostAPK() ||
                checkMultipleProcessWithSameUid() ||
                checkMultipleProcessWithSameUid_2() ||
                checkSuspiciousNativeLib() ||
                checkUndeclaredPermissionCheck() ||
                checkAppRuntimeDir() ||
                detectAndroidManagerProxyObjectsNative();
    }

    public static class TestService extends Service {
        private static final String TAG = TestService.class.getCanonicalName();

        @Nullable
        @Override
        public IBinder onBind(Intent intent) {
            throw new UnsupportedOperationException("No onBind method implemented yet");
        }

        @Override
        public int onStartCommand(Intent intent, int flags, int startId) {
            Log.d(TAG, "TestService onStartCommand invoked");
            super.onStartCommand(intent, flags, startId);
            return Service.START_NOT_STICKY;
        }
    }

}
