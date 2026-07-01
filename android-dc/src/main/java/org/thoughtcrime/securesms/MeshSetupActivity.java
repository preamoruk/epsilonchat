package org.thoughtcrime.securesms;

import android.content.Intent;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AlertDialog;
import org.thoughtcrime.securesms.connect.DcHelper;
import org.thoughtcrime.securesms.util.Prefs;
import org.thoughtcrime.securesms.util.ViewUtil;

/**
 * Mesh-based onboarding activity that replaces Delta Chat's email/IMAP/SMTP login flow.
 *
 * <p>The user can either paste/scan an invite string ({@code epsilon://<uuid>}) or generate their
 * own invite to share out-of-band. Pressing "Connect" stores the invite and proceeds to the
 * conversation list.
 */
public class MeshSetupActivity extends BaseActionBarActivity {

  private static final String TAG = "MeshSetupActivity";
  private static final String PREF_MY_INVITE = "epsilon_my_invite";
  private static final String PREF_INVITE_CONNECTED = "epsilon_invite_connected";

  private EditText inviteInput;
  private TextView myInviteLabel;
  private TextView myInviteText;
  private String myInvite;

  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.mesh_setup_activity);
    ViewUtil.applyWindowInsets(findViewById(R.id.mesh_content_container));

    Button startBtn = findViewById(R.id.btn_start);
    Button scanBtn = findViewById(R.id.btn_scan_invite);
    Button showBtn = findViewById(R.id.btn_show_invite);
    Button connectBtn = findViewById(R.id.btn_connect);
    inviteInput = findViewById(R.id.et_invite_input);
    myInviteLabel = findViewById(R.id.tv_invite_label);
    myInviteText = findViewById(R.id.tv_my_invite);

    // Restore any previously generated invite
    myInvite = Prefs.getStringPreference(this, PREF_MY_INVITE, null);

    // "Start EpsilonChat" just reveals the invite entry fields and the connect button,
    // acting as a one-tap "get started" entry point.
    startBtn.setOnClickListener(
        v -> {
          startBtn.setVisibility(View.GONE);
          inviteInput.setVisibility(View.VISIBLE);
        });

    // For now, "Scan Invite QR" just focuses the text input field. A real camera scanner
    // (ZXing IntentIntegrator) can be wired in later; the text input lets us bootstrap and
    // test the full flow without camera permissions.
    scanBtn.setOnClickListener(v -> showScanDialog());

    showBtn.setOnClickListener(v -> showMyInvite());

    connectBtn.setOnClickListener(v -> onConnect());
  }

  /** Show a dialog explaining QR scanning is not yet wired and reveal the manual entry field. */
  private void showScanDialog() {
    inviteInput.setVisibility(View.VISIBLE);
    new AlertDialog.Builder(this)
        .setTitle("Scan Invite QR")
        .setMessage(
            "Camera scanning is coming soon. For now, please paste the invite string "
                + "(epsilon://...) you received from the other party into the field below.")
        .setPositiveButton(android.R.string.ok, null)
        .show();
    inviteInput.requestFocus();
  }

  /** Generate (or restore) our own invite and display it to the user. */
  private void showMyInvite() {
    if (TextUtils.isEmpty(myInvite)) {
      myInvite = MeshInvite.generateInvite();
      Prefs.setStringPreference(this, PREF_MY_INVITE, myInvite);
    }
    myInviteLabel.setVisibility(View.VISIBLE);
    myInviteText.setText(myInvite);
    myInviteText.setVisibility(View.VISIBLE);
  }

  /** Validate the pasted invite, store it, and proceed to the conversation list. */
  private void onConnect() {
    String invite = inviteInput.getText().toString().trim();
    if (TextUtils.isEmpty(invite)) {
      Toast.makeText(this, "Please enter an invite code.", Toast.LENGTH_SHORT).show();
      return;
    }
    if (!MeshInvite.parseInvite(invite)) {
      Toast.makeText(
              this,
              "Invalid invite format. Expected epsilon://<uuid>",
              Toast.LENGTH_LONG)
          .show();
      return;
    }

    // Persist the connected invite so the app knows onboarding is done.
    Prefs.setStringPreference(this, PREF_MY_INVITE, invite);
    Prefs.setBooleanPreference(this, PREF_INVITE_CONNECTED, true);

    // Mark account as configured so the rest of the app proceeds normally.
    // We use the existing Delta Chat prefs plumbing; a full mesh backend will replace
    // this eventually, but it lets us reuse the conversation list and the rest of the UI.
    try {
      DcHelper.set(this, "configured_addr", "epsilon://" + MeshInvite.getInviteId(invite));
    } catch (Exception e) {
      // best-effort: if the native side isn't ready yet, we still proceed
    }

    Intent intent = new Intent(getApplicationContext(), ConversationListActivity.class);
    intent.putExtra(ConversationListActivity.FROM_WELCOME, true);
    startActivity(intent);
    finish();
  }
}