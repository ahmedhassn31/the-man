package com.theman.security;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.LinkAddress;

import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import com.getcapacitor.JSObject;
import com.getcapacitor.JSArray;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.ArrayList;
import java.util.List;

@CapacitorPlugin(name = "LocalNetwork")
public class LocalNetworkPlugin extends Plugin {

    @PluginMethod
    public void getInfo(PluginCall call) {
        JSObject result = new JSObject();

        try {
            ConnectivityManager cm =
                (ConnectivityManager) getContext()
                .getSystemService(Context.CONNECTIVITY_SERVICE);

            Network network = cm.getActiveNetwork();

            if (network == null) {
                result.put("connected", false);
                result.put("ip", "غير متصل");
                result.put("type", "unknown");
                call.resolve(result);
                return;
            }

            LinkProperties links = cm.getLinkProperties(network);
            NetworkCapabilities caps = cm.getNetworkCapabilities(network);

            String ip = "غير متاح";

            if (links != null) {
                for (LinkAddress address : links.getLinkAddresses()) {
                    if (address.getAddress() instanceof java.net.Inet4Address
                        && !address.getAddress().isLoopbackAddress()) {
                        ip = address.getAddress().getHostAddress();
                        break;
                    }
                }
            }

            String type = "unknown";

            if (caps != null) {
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                    type = "wifi";
                } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                    type = "cellular";
                } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                    type = "ethernet";
                }
            }

            result.put("connected", true);
            result.put("ip", ip);
            result.put("type", type);
            call.resolve(result);

        } catch (Exception e) {
            call.reject("تعذر قراءة بيانات الشبكة: " + e.getMessage(), e);
        }
    }

    @PluginMethod
    public void scanDevices(PluginCall call) {
        Process process = null;

        try {
            ConnectivityManager cm =
                (ConnectivityManager) getContext().getSystemService(
                    Context.CONNECTIVITY_SERVICE
                );

            Network network = cm.getActiveNetwork();
            LinkProperties links = network == null ? null :
                cm.getLinkProperties(network);
            NetworkCapabilities caps = network == null ? null :
                cm.getNetworkCapabilities(network);

            if (links == null || caps == null ||
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                call.reject("اتصل بشبكة Wi-Fi أولاً.");
                return;
            }

            String localIp = null;
            int prefix = -1;

            for (LinkAddress item : links.getLinkAddresses()) {
                if (item.getAddress() instanceof java.net.Inet4Address) {
                    localIp = item.getAddress().getHostAddress();
                    prefix = item.getPrefixLength();
                    break;
                }
            }

            if (localIp == null || prefix < 16 || prefix > 30) {
                call.reject("تعذر تحديد نطاق شبكة Wi-Fi.");
                return;
            }

            String[] octets = localIp.split("\\.");
            if (octets.length != 4) {
                call.reject("عنوان IP غير صالح.");
                return;
            }

            int base = (Integer.parseInt(octets[0]) << 24) |
                       (Integer.parseInt(octets[1]) << 16) |
                       (Integer.parseInt(octets[2]) << 8) |
                       Integer.parseInt(octets[3]);

            int mask = (int)(0xFFFFFFFFL << (32 - prefix));
            int networkBase = base & mask;
            int broadcast = networkBase | ~mask;
            int hostCount = broadcast - networkBase - 1;

            if (hostCount > 512) {
                call.reject("نطاق الشبكة كبير جدًا للفحص.");
                return;
            }

            ExecutorService executor = Executors.newFixedThreadPool(12);
            List<java.util.concurrent.Callable<Void>> tasks = new ArrayList<>();
            List<String> reachableIps =
                java.util.Collections.synchronizedList(new ArrayList<>());

            for (int i = 1; i <= hostCount; i++) {
                int address = networkBase + i;
                String target =
                    ((address >>> 24) & 255) + "." +
                    ((address >>> 16) & 255) + "." +
                    ((address >>> 8) & 255) + "." +
                    (address & 255);

                if (target.equals(localIp)) continue;

                final String targetIp = target;

                tasks.add(() -> {
                    Process ping = null;
                    try {
                        ping = new ProcessBuilder(
                            "/system/bin/ping", "-c", "1", "-W", "1", targetIp
                        ).redirectErrorStream(true).start();

                        int pingExit = ping.waitFor();
                        if (pingExit == 0) {
                            reachableIps.add(targetIp);
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } catch (Exception ignored) {
                    } finally {
                        if (ping != null) ping.destroy();
                    }
                    return null;
                });
            }

            try {
                executor.invokeAll(tasks, 30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw e;
            } finally {
                executor.shutdownNow();
            }

            String iface = links.getInterfaceName();
            if (iface == null || !iface.startsWith("wlan")) {
                call.reject("تعذر تحديد واجهة Wi-Fi.");
                return;
            }

            StringBuilder rawOutput = new StringBuilder();
            JSArray devices = new JSArray();
            List<String> discoveredIps = new ArrayList<>();

            try {
                process = new ProcessBuilder(
                    "/system/bin/ip", "neigh", "show", "dev", iface
                ).redirectErrorStream(true).start();

                try (java.io.BufferedReader reader =
                    new java.io.BufferedReader(
                        new java.io.InputStreamReader(process.getInputStream()))) {

                    String line;
                    while ((line = reader.readLine()) != null) {
                        rawOutput.append(line).append("\\n");
                        String[] parts = line.trim().split("\\s+");
                        if (parts.length < 2) continue;

                        String ip = parts[0];
                        String mac = null;
                        boolean failed = false;

                        for (int i = 1; i < parts.length; i++) {
                            if ("lladdr".equals(parts[i]) && i + 1 < parts.length) {
                                mac = parts[i + 1];
                            }
                            if ("FAILED".equals(parts[i]) || "INCOMPLETE".equals(parts[i])) {
                                failed = true;
                            }
                        }

                        if (failed || mac == null || ip.equals(localIp) ||
                            mac.equals("00:00:00:00:00:00")) continue;

                        JSObject device = new JSObject();
                        device.put("ip", ip);
                        device.put("mac", mac);
                        devices.put(device);
                        discoveredIps.add(ip);
                    }
                }

                int exitCode = process.waitFor();
                rawOutput.append("\\nExit code: ").append(exitCode);

            } catch (Exception e) {
                rawOutput.append("\\nNeighbor table error: ").append(e.getMessage());
                if (process != null) process.destroy();
                process = null;
            }

            for (String ip : reachableIps) {
                if (!discoveredIps.contains(ip)) {
                    JSObject device = new JSObject();
                    device.put("ip", ip);
                    device.put("mac", "غير متاح");
                    devices.put(device);
                    discoveredIps.add(ip);
                }
            }

            JSObject result = new JSObject();
            result.put("devices", devices);
            result.put("count", devices.length());
            result.put("debug", rawOutput.toString());
            result.put("interface", iface);
            result.put("localIp", localIp);
            call.resolve(result);

        } catch (Exception e) {
            call.reject("تعذر فحص الأجهزة: " + e.getMessage(), e);
        } finally {
            if (process != null) process.destroy();
        }
    }
}
