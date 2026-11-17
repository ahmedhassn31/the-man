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
}
