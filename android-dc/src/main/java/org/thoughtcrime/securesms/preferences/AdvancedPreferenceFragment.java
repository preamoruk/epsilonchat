package org.thoughtcrime.securesms.preferences;

import static android.app.Activity.RESULT_OK;
import static android.text.InputType.TYPE_TEXT_VARIATION_URI;
import static org.thoughtcrime.securesms.connect.DcHelper.CONFIG_BCC_SELF;
import static org.thoughtcrime.securesms.connect.DcHelper.CONFIG_STATS_SENDING;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.preference.CheckBoxPreference;
import androidx.preference.Preference;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;
import org.thoughtcrime.securesms.ApplicationPreferencesActivity;
import org.thoughtcrime.securesms.LogViewActivity;
import org.thoughtcrime.securesms.R;
import org.thoughtcrime.securesms.StatsSending;
import org.thoughtcrime.securesms.WalletActivity;
import org.thoughtcrime.securesms.connect.DcEventCenter;
import org.thoughtcrime.securesms.proxy.ProxySettingsActivity;
import org.thoughtcrime.securesms.relay.RelayListActivity;
import org.thoughtcrime.securesms.util.Prefs;
import org.thoughtcrime.securesms.util.ScreenLockUtil;
import org.thoughtcrime.securesms.util.StreamUtil;
import org.thoughtcrime.securesms.util.Util;

public class AdvancedPreferenceFragment extends ListSummaryPreferenceFragment
    implements DcEventCenter.DcEventDelegate {
  private static final String TAG = "AdvancedPreferenceFragment";

  CheckBoxPreference selfReportingCheckbox;
  CheckBoxPreference multiDeviceCheckbox;
  private ActivityResultLauncher<Intent> screenLockLauncher;

  @Override
  public void onCreate(Bundle paramBundle) {
    super.onCreate(paramBundle);

    screenLockLauncher =
        registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
              if (result.getResultCode() == RESULT_OK) {
                openRelayListActivity();
              }
            });

    multiDeviceCheckbox = (CheckBoxPreference) this.findPreference("pref_bcc_self");
    if (multiDeviceCheckbox != null) {
      multiDeviceCheckbox.setOnPreferenceChangeListener(
          (preference, newValue) -> {
            boolean enabled = (Boolean) newValue;
            if (enabled) {
              dcContext.setConfigInt(CONFIG_BCC_SELF, 1);
              return true;
            } else {
              new AlertDialog.Builder(requireContext())
                  .setMessage(R.string.pref_multidevice_change_warn)
                  .setPositiveButton(
                      R.string.ok,
                      (dialogInterface, i) -> {
                        dcContext.setConfigInt(CONFIG_BCC_SELF, 0);
                        ((CheckBoxPreference) preference).setChecked(false);
                      })
                  .setNegativeButton(R.string.cancel, null)
                  .show();
              return false;
            }
          });
    }

    Preference screenSecurity = this.findPreference(Prefs.SCREEN_SECURITY_PREF);
    if (screenSecurity != null) {
      screenSecurity.setOnPreferenceChangeListener(new ScreenShotSecurityListener());
    }

    Preference submitDebugLog = this.findPreference("pref_view_log");
    if (submitDebugLog != null) {
      submitDebugLog.setOnPreferenceClickListener(new ViewLogListener());
    }

    Preference webxdcStore = this.findPreference(Prefs.WEBXDC_STORE_URL_PREF);
    if (webxdcStore != null) {
      webxdcStore.setOnPreferenceClickListener(new WebxdcStoreUrlListener());
    }
    updateWebxdcStoreSummary();

    Preference locationStreamingEnabled = this.findPreference("pref_location_streaming_enabled");
    if (locationStreamingEnabled != null) {
      locationStreamingEnabled.setOnPreferenceChangeListener(
          (preference, newValue) -> {
            if ((Boolean) newValue) {
              new AlertDialog.Builder(requireActivity())
                  .setTitle("Thanks for trying out \"Location Streaming\"!")
                  .setMessage(
                      "• You will find a corresponding option in the attach menu (the paper clip) of each chat now\n\n"
                          + "• If you want to quit the experimental feature, you can disable it at \"Settings / Advanced\"")
                  .setCancelable(false)
                  .setPositiveButton(R.string.ok, null)
                  .show();
            }
            return true;
          });
    }

    selfReportingCheckbox = this.findPreference("pref_stats_sending");
    if (selfReportingCheckbox != null) {
      selfReportingCheckbox.setOnPreferenceChangeListener(
          (preference, newValue) -> {
            boolean enabled = (Boolean) newValue;
            if (enabled) {
              StatsSending.showStatsConfirmationDialog(
                  requireActivity(),
                  () -> {
                    ((CheckBoxPreference) preference).setChecked(true);
                  });
              return false;
            } else {
              dcContext.setConfigInt(CONFIG_STATS_SENDING, 0);
              return true;
            }
          });
    }

    Preference proxySettings = this.findPreference("proxy_settings_button");
    if (proxySettings != null) {
      proxySettings.setOnPreferenceClickListener(
          (preference) -> {
            startActivity(new Intent(requireActivity(), ProxySettingsActivity.class));
            return true;
          });
    }

    Preference relayListBtn = this.findPreference("pref_relay_list_button");
    if (relayListBtn != null) {
      relayListBtn.setOnPreferenceClickListener(
          ((preference) -> {
            boolean result =
                ScreenLockUtil.applyScreenLock(
                    requireActivity(),
                    getString(R.string.transports),
                    getString(R.string.enter_system_secret_to_continue),
                    screenLockLauncher);
            if (!result) {
              openRelayListActivity();
            }
            return true;
          }));
    }

    initEpsilonMiningPreferences();
  }

  // ---- Epsilon Mining & Wallet ----

  /** Preference keys for the Epsilon Mining & Wallet category. */
  private static final String PREF_EPSILON_BALANCE = "pref_epsilon_balance";
  private static final String PREF_EPSILON_MINING_SPEED = "pref_epsilon_mining_speed";
  private static final String PREF_EPSILON_DO_NOT_MINE = "pref_epsilon_do_not_mine";
  private static final String PREF_EPSILON_WALLET_ADDRESS = "pref_epsilon_wallet_address";
  private static final String PREF_EPSILON_OPEN_WALLET = "pref_epsilon_open_wallet";

  private void initEpsilonMiningPreferences() {
    // "Do not mine" toggle — inverse of epsilonIsMiningEnabled().
    CheckBoxPreference doNotMinePref = (CheckBoxPreference) this.findPreference(PREF_EPSILON_DO_NOT_MINE);
    if (doNotMinePref != null) {
      // Set initial state from core (mining enabled => "do not mine" unchecked).
      try {
        doNotMinePref.setChecked(!dcContext.epsilonIsMiningEnabled());
      } catch (Exception e) {
        Log.w(TAG, "epsilonIsMiningEnabled() failed", e);
      }
      doNotMinePref.setOnPreferenceChangeListener(
          (preference, newValue) -> {
            boolean doNotMine = (Boolean) newValue;
            boolean miningEnabled = !doNotMine;
            Util.runOnBackground(
                () -> {
                  try {
                    dcContext.epsilonSetMiningEnabled(miningEnabled);
                  } catch (Exception e) {
                    Log.w(TAG, "epsilonSetMiningEnabled() failed", e);
                  }
                  requireActivity()
                      .runOnUiThread(
                          () -> updateEpsilonMiningSpeedSummary(miningEnabled));
                });
            return true;
          });
    }

    // "Open Wallet" button launches WalletActivity.
    Preference openWalletPref = this.findPreference(PREF_EPSILON_OPEN_WALLET);
    if (openWalletPref != null) {
      openWalletPref.setOnPreferenceClickListener(
          preference -> {
            startActivity(new Intent(requireActivity(), WalletActivity.class));
            return true;
          });
    }

    // The balance preference also opens the wallet activity when tapped.
    Preference balancePref = this.findPreference(PREF_EPSILON_BALANCE);
    if (balancePref != null) {
      balancePref.setOnPreferenceClickListener(
          preference -> {
            startActivity(new Intent(requireActivity(), WalletActivity.class));
            return true;
          });
    }
  }

  /** Reads balance + mining speed + wallet address from core and updates the preference summaries. */
  private void updateEpsilonSummaries() {
    Util.runOnBackground(
        () -> {
          String balanceJson = "";
          double miningSpeed = 0.0;
          boolean miningEnabled = false;
          String walletAddress = "";
          try {
            balanceJson = dcContext.epsilonGetBalance();
          } catch (Exception e) {
            Log.w(TAG, "epsilonGetBalance() failed", e);
          }
          try {
            miningEnabled = dcContext.epsilonIsMiningEnabled();
          } catch (Exception e) {
            Log.w(TAG, "epsilonIsMiningEnabled() failed", e);
          }
          try {
            miningSpeed = dcContext.epsilonGetMiningSpeed();
          } catch (Exception e) {
            Log.w(TAG, "epsilonGetMiningSpeed() failed", e);
          }
          try {
            walletAddress = dcContext.epsilonGetWalletAddress();
          } catch (Exception e) {
            Log.w(TAG, "epsilonGetWalletAddress() failed", e);
          }

          final double sol = parseJsonDouble(balanceJson, "sol");
          final double eps = parseJsonDouble(balanceJson, "eps");
          final boolean enabled = miningEnabled;
          final double speed = miningSpeed;
          final String address = walletAddress;

          requireActivity()
              .runOnUiThread(
                  () -> {
                    Preference balPref = findPreference(PREF_EPSILON_BALANCE);
                    if (balPref != null) {
                      balPref.setSummary(
                          getString(
                              R.string.pref_epsilon_balance_summary,
                              String.format(java.util.Locale.US, "%.6f", sol),
                              String.format(java.util.Locale.US, "%.4f", eps)));
                    }
                    updateEpsilonMiningSpeedSummary(enabled, speed);

                    Preference addrPref = findPreference(PREF_EPSILON_WALLET_ADDRESS);
                    if (addrPref != null) {
                      if (address == null || address.isEmpty()) {
                        addrPref.setSummary(getString(R.string.none));
                      } else {
                        addrPref.setSummary(address);
                      }
                    }
                  });
        });
  }

  private void updateEpsilonMiningSpeedSummary(boolean miningEnabled) {
    updateEpsilonMiningSpeedSummary(miningEnabled, 0.0);
  }

  private void updateEpsilonMiningSpeedSummary(boolean miningEnabled, double speed) {
    Preference speedPref = findPreference(PREF_EPSILON_MINING_SPEED);
    if (speedPref != null) {
      if (miningEnabled) {
        speedPref.setSummary(getString(R.string.pref_epsilon_mining_speed_summary, speed));
      } else {
        speedPref.setSummary(getString(R.string.pref_epsilon_mining_speed_summary_disabled));
      }
    }
  }

  /** Parse a double from a tiny JSON object such as {"sol":0.0,"eps":0.0}. */
  private static double parseJsonDouble(String json, String key) {
    if (json == null) return 0.0;
    String needle = "\"" + key + "\"";
    int i = json.indexOf(needle);
    if (i < 0) return 0.0;
    int colon = json.indexOf(':', i);
    if (colon < 0) return 0.0;
    int start = colon + 1;
    while (start < json.length() && Character.isWhitespace(json.charAt(start))) start++;
    int end = start;
    while (end < json.length()
        && (Character.isDigit(json.charAt(end))
            || json.charAt(end) == '-'
            || json.charAt(end) == '+'
            || json.charAt(end) == '.'
            || json.charAt(end) == 'e'
            || json.charAt(end) == 'E')) {
      end++;
    }
    if (end == start) return 0.0;
    try {
      return Double.parseDouble(json.substring(start, end));
    } catch (NumberFormatException e) {
      return 0.0;
    }
  }

  @Override
  public void onCreatePreferences(@Nullable Bundle savedInstanceState, String rootKey) {
    addPreferencesFromResource(R.xml.preferences_advanced);
  }

  @Override
  public void onResume() {
    super.onResume();
    Objects.requireNonNull(
            ((ApplicationPreferencesActivity) requireActivity()).getSupportActionBar())
        .setTitle(R.string.menu_advanced);

    selfReportingCheckbox.setChecked(0 != dcContext.getConfigInt(CONFIG_STATS_SENDING));
    multiDeviceCheckbox.setChecked(0 != dcContext.getConfigInt(CONFIG_BCC_SELF));

    // Refresh the Epsilon Mining & Wallet summaries every time the page is shown.
    updateEpsilonSummaries();
  }

  protected File copyToCacheDir(Uri uri) throws IOException {
    try (InputStream inputStream = requireActivity().getContentResolver().openInputStream(uri)) {
      File file = File.createTempFile("tmp-keys-file", ".tmp", requireActivity().getCacheDir());
      try (OutputStream outputStream = new FileOutputStream(file)) {
        StreamUtil.copy(inputStream, outputStream);
      }
      return file;
    }
  }

  public static @NonNull String getVersion(@Nullable Context context) {
    try {
      if (context == null) return "";

      String app = context.getString(R.string.app_name);
      String version =
          context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionName;

      return String.format("%s %s", app, version);
    } catch (PackageManager.NameNotFoundException e) {
      Log.w(TAG, e);
      return context.getString(R.string.app_name);
    }
  }

  private class ScreenShotSecurityListener implements Preference.OnPreferenceChangeListener {
    @Override
    public boolean onPreferenceChange(@NonNull Preference preference, Object newValue) {
      boolean enabled = (Boolean) newValue;
      Prefs.setScreenSecurityEnabled(getContext(), enabled);
      Toast.makeText(
              getContext(), R.string.pref_screen_security_please_restart_hint, Toast.LENGTH_LONG)
          .show();
      return true;
    }
  }

  private class ViewLogListener implements Preference.OnPreferenceClickListener {
    @Override
    public boolean onPreferenceClick(@NonNull Preference preference) {
      final Intent intent = new Intent(requireActivity(), LogViewActivity.class);
      startActivity(intent);
      return true;
    }
  }

  private class WebxdcStoreUrlListener implements Preference.OnPreferenceClickListener {
    @Override
    public boolean onPreferenceClick(@NonNull Preference preference) {
      View gl = View.inflate(requireActivity(), R.layout.single_line_input, null);
      EditText inputField = gl.findViewById(R.id.input_field);
      inputField.setHint(Prefs.DEFAULT_WEBXDC_STORE_URL);
      inputField.setText(Prefs.getWebxdcStoreUrl(requireActivity()));
      inputField.setSelection(inputField.getText().length());
      inputField.setInputType(TYPE_TEXT_VARIATION_URI);
      new AlertDialog.Builder(requireActivity())
          .setTitle(R.string.webxdc_store_url)
          .setMessage(R.string.webxdc_store_url_explain)
          .setView(gl)
          .setNegativeButton(android.R.string.cancel, null)
          .setPositiveButton(
              android.R.string.ok,
              (dlg, btn) -> {
                Prefs.setWebxdcStoreUrl(requireActivity(), inputField.getText().toString());
                updateWebxdcStoreSummary();
              })
          .show();
      return true;
    }
  }

  private void updateWebxdcStoreSummary() {
    Preference preference = this.findPreference(Prefs.WEBXDC_STORE_URL_PREF);
    if (preference != null) {
      preference.setSummary(Prefs.getWebxdcStoreUrl(requireActivity()));
    }
  }

  private void openRelayListActivity() {
    Intent intent = new Intent(requireActivity(), RelayListActivity.class);
    startActivity(intent);
  }
}
