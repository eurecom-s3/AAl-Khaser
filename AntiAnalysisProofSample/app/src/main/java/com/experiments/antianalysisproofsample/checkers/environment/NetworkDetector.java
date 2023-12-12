package com.experiments.antianalysisproofsample.checkers.environment;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.text.TextUtils;
import android.util.Log;

import androidx.core.content.ContextCompat;

import com.experiments.antianalysisproofsample.R;
import com.experiments.antianalysisproofsample.utils.BooleanHolder;
import com.experiments.antianalysisproofsample.utils.GenericHelper;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;

import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.ResponseBody;

public class NetworkDetector {
    private static final String TAG = NetworkDetector.class.getCanonicalName();

    private static final String IP = "10.0.2.15";
    private static final String[] KNOWN_PUBLIC_IPS = {
            "xyz.xyz.xyz.xyz", // TODO: Update with list
    };

    private final Context mContext;
    private final boolean[] detectAdbOverWifiResult;
    private final boolean[] detectAdbOverWifiFinish;
    private final boolean[] detectProblemSslPinningOkHttpResult;
    private final boolean[] detectProblemSslPinningOkHttpFinish;

    public NetworkDetector(Context mContext) {
        this.mContext = mContext;

        detectAdbOverWifiResult = new boolean[1];
        detectAdbOverWifiResult[0] = false;
        detectAdbOverWifiFinish = new boolean[1];
        detectAdbOverWifiFinish[0] = false;

        detectProblemSslPinningOkHttpResult = new boolean[1];
        detectProblemSslPinningOkHttpResult[0] = false;
        detectProblemSslPinningOkHttpFinish = new boolean[1];
        detectProblemSslPinningOkHttpFinish[0] = false;
    }

    // Check eth0 interface
    public boolean detectEthInterface() {
        boolean result = false;
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ) {
                NetworkInterface intf = en.nextElement();
                if (intf.getName().equals("eth0")) {
                    result = true;
                    break;
                }
            }
        } catch (Exception e) {
            Log.d(TAG,"Error on detectEthInterface. Message: " + e.toString());
        }

        Log.d(TAG, "* detectEthInterface: " + result);
        return result;
    }

    // Detect emulator IP
    public boolean detectEmulatorIp() {
        boolean result = false;

        if (ContextCompat.checkSelfPermission(this.mContext, Manifest.permission.INTERNET) == PackageManager.PERMISSION_GRANTED) {
            String[] args = {"/system/bin/netcfg"};
            StringBuilder stringBuilder = new StringBuilder();

            try (InputStream inputStream = new ProcessBuilder(args)
                    .directory((new File("/system/bin/")))
                    .redirectErrorStream(true)
                    .start()
                    .getInputStream()) {

                byte[] readBuffer = new byte[1024];
                while (inputStream.read(readBuffer) != -1)
                    stringBuilder.append(new String(readBuffer));

            } catch (Exception ex) { /*Ignore exception*/ }

            String netData = stringBuilder.toString();

            if (!TextUtils.isEmpty(netData)) {
                String[] array = netData.split("\n");

                for (String lan : array)
                    if ((lan.contains("wlan0") || lan.contains("tunl0") || lan.contains("eth0"))
                            && lan.contains(IP)) {
                        result = true;
                        break;
                    }
            }
        }

        Log.d(TAG, "* detectEmulatorIp: " + result);
        return result;
    }

    // Detect known public IPs
    public boolean detectKnownPublicIps() {
        boolean result = false;
        try {
            URL url = new URL("https://www.maxmind.com/geoip/v2.1/city/me");
            HttpURLConnection http = (HttpURLConnection) url.openConnection();
            http.setRequestProperty("Referer", "https://www.maxmind.com/en/locate-my-ip-address/");
            http.setRequestProperty("user-agent", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)");

            // System.out.println(http.getResponseCode() + " " + http.getResponseMessage());
            if (http.getResponseCode() == 200) {
                // retrieve the response
                BufferedReader br = new BufferedReader(new InputStreamReader(http.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    response.append(line);
                }

                // TODO: Check also other infos, such as isp, organization, domain, etc..
                //  and improve the parsing of the json with gson library!
                int startIndex = response.indexOf("ip_address") + 13;
                int endIndex = response.indexOf("\"", startIndex);
                String ip = response.substring(startIndex, endIndex);

                result = Arrays.asList(KNOWN_PUBLIC_IPS).contains(ip);
            }

            http.disconnect();
        } catch (Exception e) { /* Ignore */ }

        Log.d(TAG, "* detectKnownPublicIps : " + result);
        return result;
    }

    private InetAddress intToInetAddress(int hostAddress) {
        byte[] addressBytes = new byte[] {
                (byte) (0xff & hostAddress),
                (byte) (0xff & (GenericHelper.rotateLeft(8, hostAddress))),
                (byte) (0xff & (GenericHelper.rotateLeft(16, hostAddress))),
                (byte) (0xff & (GenericHelper.rotateLeft(24, hostAddress)))};

        try {
            return InetAddress.getByAddress(addressBytes);
        } catch (UnknownHostException e) {
            Log.e(TAG, "InetAddress error. Message = " + e.toString());
        }

        return null;
    }

    private String getWifiIpAddress(WifiManager wifiManager) {
        int intRepresentation = wifiManager.getDhcpInfo().ipAddress;
        InetAddress addr = intToInetAddress(intRepresentation);

        if (addr == null)
            return null;

        return addr.getHostAddress();
    }

    /*Checks whether the device is listening to port 5555. This port is used to connect to a computer through wifi on a local network for ADB debugging*/
    public boolean detectAdbOverWifi() {
        final boolean[] result = {false};
        WifiManager mgr = this.mContext.getSystemService(WifiManager.class);

        if (this.mContext.checkSelfPermission(Manifest.permission.ACCESS_WIFI_STATE) != PackageManager.PERMISSION_GRANTED) {
            return result[0];
        }

        if(!mgr.isWifiEnabled()) {
            return result[0];
        }

        BooleanHolder bh = new BooleanHolder();
        new Thread(new Runnable() {
            @Override
            public void run() {

                String wifiAddress = getWifiIpAddress(mgr);
                try {
                    // SocketFactory.getDefault().createSocket(wifiAddress, 5555).close();
                    Socket socket = new Socket();
                    socket.connect(new InetSocketAddress(wifiAddress, 5555), 2000);
                    result[0] = true;
                    socket.close();
                } catch (Exception e) {
                    Log.d(TAG, "No open adb port 5555");
                }

                synchronized (bh) {
                    bh.isTaskFinished = true;
                    bh.notify();
                }
            }
        }).start();

        synchronized (bh) {
            while (!bh.isTaskFinished) {
                try {
                    bh.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }

        Log.d(TAG, "* detectAdbOverWifi : " + result[0]);
        return result[0];
    }

    public boolean detectVpn() {
        boolean result = false;
        ConnectivityManager mgr = this.mContext.getSystemService(ConnectivityManager.class);

        for (Network network : mgr.getAllNetworks()) {
            NetworkCapabilities capabilities = mgr.getNetworkCapabilities(network);

            if(capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                result = true;
                break;
            }
        }

        Log.d(TAG, "* detectVpn : " + result);
        return result;
    }

    public boolean detectFirewall() {
        boolean result = false;
        PackageManager packageManager = this.mContext.getPackageManager();

        List<PackageInfo> packages;
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            packages = packageManager.getInstalledPackages(PackageManager.MATCH_UNINSTALLED_PACKAGES);
        } else {
            packages = packageManager.getInstalledPackages(PackageManager.GET_UNINSTALLED_PACKAGES);
        }

        for (PackageInfo app : packages) {
            String name = app.packageName.toLowerCase();
            if (name.contains("firewall") || name.contains("adb")
                    || name.contains("port scanner") || name.contains("network scanner")
                    || name.contains("network analysis") || name.contains("ip tools")
                    || name.contains("net scan") || name.contains("network analyzer")
                    || name.contains("packet capture") || name.contains("pcap") || name.contains("wicap")
                    || name.contains("netcapture") || name.contains("sniffer") || name.contains("vnet") || name.contains("network log") ||
                    name.contains("network monitor") || name.contains("network tools") || name.contains("network utilities") || name.contains("network utility")) {
                result = true;
                break;
            }
        }

        Log.d(TAG, "* detectFirewall : " + result);
        return result;
    }

    // NOTE: this is only a possible implementation for ssl pinning (I tested the google.com certifacte)
    // NOTE: THIS MAY CHANGE IN FUTURE
    public boolean detectProblemSslPinningOkHttp() {
        final boolean[] result = {true};

        BooleanHolder bh = new BooleanHolder();
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    OkHttpClient client = new OkHttpClient.Builder()
                            .certificatePinner(new CertificatePinner.Builder()
                                    .add("google.com", "sha256/z7gm8rsrPuLSbvOLgadXNp86DAjmlZSSPYd847B6fnU=")
                                    .add("google.com", "sha256/zCTnfLwLKbS9S2sbp+uFz4KZOocFvXxkV06Ce9O5M2w=")
                                    .add("google.com", "sha256/hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc=")
                                    .add("www.google.com", "sha256/z7gm8rsrPuLSbvOLgadXNp86DAjmlZSSPYd847B6fnU=")
                                    .add("www.google.com", "sha256/zCTnfLwLKbS9S2sbp+uFz4KZOocFvXxkV06Ce9O5M2w=")
                                    .add("www.google.com", "sha256/hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc=")
                                    .build())
                            .build();

                    Request request = new Request.Builder()
                            .url("https://www.google.com")
                            .build();
                    ResponseBody body = client.newCall(request).execute().body();
                    Log.d(TAG, "response body is " + body);
                    String string = Objects.requireNonNull(body).string();

                    if (string.contains("Google")) {
                        result[0] = false;
                    }
                } catch (Exception e) { /* Ignore */
                    e.printStackTrace();
                }

                synchronized (bh) {
                    bh.isTaskFinished = true;
                    bh.notify();
                }
            }
        }).start();

        synchronized (bh) {
            while (!bh.isTaskFinished) {
                try {
                    bh.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }

        Log.d(TAG, "* checkSslPinning : " + result[0]);
        return result[0];
    }

    public boolean isEmulatorArtifactDetected() {
        return detectEthInterface() ||
                detectEmulatorIp();
    }

    public boolean isArtifactDetected() {
        return detectAdbOverWifi() ||
                detectVpn() ||
                detectFirewall() ||
                detectEthInterface() ||
                detectEmulatorIp() ||
                // detectKnownPublicIps() ||
                detectProblemSslPinningOkHttp();
    }
}
