package moe.shizuku.manager

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.FragmentActivity

object AppLock {
    var unlocked = false
        private set

    fun prompt(activity: FragmentActivity, onSuccess: () -> Unit) {
        val km = activity.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        if (km == null || !km.isDeviceSecure) {
            unlocked = true
            onSuccess()
            return
        }

        val launcher = activity.registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                unlocked = true
                onSuccess()
            } else {
                activity.finish()
            }
        }

        val intent = km.createConfirmDeviceCredentialIntent(
            "Unlock",
            "Fingerprint ya phone ka PIN daalo"
        )
        if (intent == null) {
            unlocked = true
            onSuccess()
        } else {
            launcher.launch(intent)
        }
    }
}
