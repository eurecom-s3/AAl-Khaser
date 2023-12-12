package com.experiments.antianalysisproofsample.checkers.tampering;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import com.experiments.antianalysisproofsample.BuildConfig;
import com.experiments.antianalysisproofsample.models.safetynet.SafetyNetWrapper;
import com.experiments.antianalysisproofsample.models.safetynet.AttestationStatement;
import com.experiments.antianalysisproofsample.utils.BooleanHolder;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

public class GenericDetector {
    private static final String TAG = GenericDetector.class.getCanonicalName();

    private final Context mContext;
    private final SafetyNetWrapper safetyNetWrapper;

    public GenericDetector(Context mContext) {
        this.mContext = mContext;

        this.safetyNetWrapper = new SafetyNetWrapper(mContext, new BooleanHolder());
    }

    public boolean detectFakeApkSignatureFromApk() {
        boolean result = false;

        String packageName = this.mContext.getPackageName();
        PackageManager pm = this.mContext.getPackageManager();

        try {
            ApplicationInfo applicationInfo = pm.getApplicationInfo(packageName, 0);

            String apkPath = applicationInfo.publicSourceDir;
            Log.d(TAG, apkPath);

            ZipFile zipFile = new ZipFile(apkPath);
            File file = new File(apkPath);
            ZipInputStream zin = new ZipInputStream(new FileInputStream(file));
            try {
                ZipEntry ze = null;
                while ((ze = zin.getNextEntry()) != null) {
                    if (ze.getName().startsWith("META-INF/") ) {
                       Log.d(TAG, "metainf");
                        if ((ze.getName().endsWith(".RSA") ||
                                    ze.getName().endsWith(".DSA") ||
                                    ze.getName().endsWith(".EC"))) {
                            BufferedInputStream bis = new BufferedInputStream(zipFile.getInputStream(ze));
                            byte[] content1 = new byte[bis.available()];
                            try {
                                bis.read(content1);

                                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                                InputStream signatureIn = new ByteArrayInputStream(content1);
                                Certificate cert = cf.generateCertificate(signatureIn);

                                final MessageDigest md = MessageDigest.getInstance("SHA");
                                md.update(cert.getEncoded());
                                final String signatureBase64 = new String(Base64.encode(md.digest(), Base64.DEFAULT));
                                if (!BuildConfig.SIGNATURE_BASE64.equals(signatureBase64.trim())) {
                                    result = true;
                                }

                            } finally {
                                bis.close();
                                zin.closeEntry();
                                break;
                            }
                        }
                    }
                }
            } finally {
                zin.close();
            }
        } catch (Throwable x) { /* Ignore */ }

        return result;
    }

    // Signature verification in both C and Java
    public boolean detectFakeApkSignatureFromAndroidAPI() {
        boolean result = false;

        PackageManager packageManager = this.mContext.getPackageManager();
        try {
            final Signature[] signatures;
            if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                final PackageInfo packageInfo = packageManager.getPackageInfo(this.mContext.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
                signatures = packageInfo.signingInfo.getApkContentsSigners();
            } else {
                signatures = packageManager.getPackageInfo(this.mContext.getPackageName(), PackageManager.GET_SIGNATURES).signatures;
            }
            final MessageDigest md = MessageDigest.getInstance("SHA");
            for (Signature signature : signatures) {
                byte[] bytes = signature.toByteArray();
                md.update(bytes);
                final String signatureBase64 = new String(Base64.encode(md.digest(), Base64.DEFAULT));
                if (!BuildConfig.SIGNATURE_BASE64.equals(signatureBase64.trim())) {
                    result = true;
                }

                // For the POC I assume to check only the first returned signature
                break;
            }
        } catch (PackageManager.NameNotFoundException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return result;
    }

    public boolean detectFakeInstallerSource() {
        String installerPackageName = null;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
            try {
                InstallSourceInfo installSourceInfo =
                        this.mContext.getPackageManager().getInstallSourceInfo(this.mContext.getPackageName());
                installerPackageName = installSourceInfo.getInstallingPackageName();
            } catch (PackageManager.NameNotFoundException e) { /* TODO: Virtual env?!? */ }
        } else {
            installerPackageName =
                    this.mContext.getPackageManager().getInstallerPackageName(this.mContext.getPackageName());
        }
        boolean result;
        if (BuildConfig.INSTALLER_PKG_NAME == null) {
            result = installerPackageName != null;
        } else {
            result = !(BuildConfig.INSTALLER_PKG_NAME).equals(installerPackageName);
        }

        Log.d(TAG, "* detectFakeInstallerSource: " + result);
        return result;
    }

    public boolean safetyNetBasicIntegrityFailed() {
        BooleanHolder bh = safetyNetWrapper.getBh();
        synchronized (bh) {
            while (!bh.isTaskFinished) {
                try {
                    bh.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }

        AttestationStatement stmt = safetyNetWrapper.getStmt();
        if (stmt == null) {
            throw new IllegalStateException("No SafetyNet API");
        }
        boolean result = !stmt.hasBasicIntegrity();
        Log.d(TAG, "* safetyNetBasicIntegrityFailed : " + result);
        return result;
    }

    public boolean safetyNetCtsIntegrityFailed() {
        BooleanHolder bh = safetyNetWrapper.getBh();
        synchronized (bh) {
            while (!bh.isTaskFinished) {
                try {
                    bh.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }

        AttestationStatement stmt = safetyNetWrapper.getStmt();
        if (stmt == null) {
            throw new IllegalStateException("No SafetyNet API");
        }

        boolean result = !stmt.isCtsProfileMatch();
        Log.d(TAG, "* safetyNetCtsIntegrityFailed : " + result);
        return result;
    }

    public boolean isArtifactDetected() {
        return detectFakeInstallerSource() ||
                safetyNetBasicIntegrityFailed() ||
                safetyNetCtsIntegrityFailed();
    }

}
