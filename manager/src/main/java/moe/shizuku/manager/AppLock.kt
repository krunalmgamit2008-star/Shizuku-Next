package moe.shizuku.manager

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

object AppLock {
    var unlocked = false
        private set

    fun prompt(activity: FragmentActivity, onSuccess: () -> Unit) {
        val can = BiometricManager.from(activity).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
        if (can != BiometricManager.BIOMETRIC_SUCCESS) {
            unlocked = true; onSuccess(); return
        }
        BiometricPrompt(
            activity, ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    unlocked = true; onSuccess()
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    activity.finish()
                }
            }
        ).authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock")
                .setSubtitle("Fingerprint ya phone ka PIN daalo")
                .setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL
                )
                .build()
        )
    }
}
