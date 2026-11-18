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
        JSArray devices = new JSArray();
        Process process = null;

        try {
            process = new ProcessBuilder(
                "/system/bin/ip", "neigh", "show", "dev", "wlan0"
            ).redirectErrorStream(true).start();

            try (java.io.BufferedReader reader =
                    new java.io.BufferedReader(
                        new java.io.InputStreamReader(process.getInputStream()))) {

                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.trim().split("\\s+");
                    if (parts.length < 4) continue;

                    String ip = parts[0];
                    String mac = null;

                    for (int i = 0; i < parts.length - 1; i++) {
                        if ("lladdr".equals(parts[i])) {
                            mac = parts[i + 1];
                            break;
                        }
                    }

                    if (mac == null || mac.equals("00:00:00:00:00:00")) {
                        continue;
                    }

                    JSObject device = new JSObject();
                    device.put("ip", ip);
                    device.put("mac", mac);
                    devices.put(device);
                }
            }

            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new Exception("فشل أمر قراءة جدول الشبكة: " + exitCode);
            }

            JSObject result = new JSObject();
            result.put("devices", devices);
            result.put("count", devices.length());
            call.resolve(result);

        } catch (Exception e) {
            call.reject("تعذر قراءة الأجهزة: " + e.getMessage(), e);
        } finally {
            if (process != null) process.destroy();
        }
    }
}
