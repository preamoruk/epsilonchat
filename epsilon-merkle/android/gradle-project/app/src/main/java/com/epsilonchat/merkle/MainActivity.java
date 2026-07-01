package com.epsilonchat.merkle;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.WebSettings;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;

public class MainActivity extends Activity {
    private WebView webView;
    private static final String SERVER_URL = "http://192.168.1.139:8848";
    private static final String LOCAL_FALLBACK = "file:///android_asset/index.html";
    private boolean serverLoaded = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                serverLoaded = true;
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (!serverLoaded && request.getUrl() != null && request.getUrl().toString().startsWith("http")) {
                    view.loadUrl(LOCAL_FALLBACK);
                }
            }
        });

        // Try Mac server first
        webView.loadUrl(SERVER_URL);

        // After 5 seconds, check if page loaded; if not, fall back to local
        new Handler().postDelayed(new Runnable() {
            @Override
            public void run() {
                if (!serverLoaded) {
                    webView.loadUrl(LOCAL_FALLBACK);
                }
            }
        }, 5000);

        setContentView(webView);
    }

    @Override
    public void onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }
}