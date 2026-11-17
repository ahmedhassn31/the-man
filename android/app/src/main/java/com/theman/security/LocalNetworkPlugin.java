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

        try (BufferedReader reader =
                 new BufferedReader(new FileReader("/proc/net/arp"))) {

            String line;
            reader.readLine();

            while ((line = reader.readLine()) != null) {
                String[] parts = line.trim().split("\\s+");

                if (parts.length >= 4
                    && !parts[0].equals("0.0.0.0")
                    && !parts[3].equals("00:00:00:00:00:00")) {

                    JSObject device = new JSObject();
                    device.put("ip", parts[0]);
                    device.put("mac", parts[3]);
                    devices.put(device);
                }
            }

            JSObject result = new JSObject();
            result.put("devices", devices);
            result.put("count", devices.length());
            call.resolve(result);

        } catch (Exception e) {
            call.reject("تعذر قراءة الأجهزة: " + e.getMessage(), e);
        }
    }
}
