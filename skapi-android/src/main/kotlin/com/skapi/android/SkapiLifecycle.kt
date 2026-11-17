package com.skapi.android

import android.app.Activity
import android.app.Application
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.os.Bundle
import com.skapi.Skapi

/**
 * Tells a Skapi object when the app comes back to the foreground and when the network comes back,
 * as skapi-js listens to visibilitychange and online in a browser:
 *
 *     class App : Application() {
 *         lateinit var skapi: Skapi
 *         override fun onCreate() {
 *             super.onCreate()
 *             skapi = Skapi("<Project ID>", storage = SharedPreferencesStorage(this))
 *             SkapiLifecycle.watch(this, skapi)
 *         }
 *     }
 *
 * On each return a temporary (anonymous) account is checked at once, and the realtime connection
 * is checked and reconnected if it dropped while the app was in the background.
 */
public class SkapiLifecycle private constructor(
    private val application: Application,
    private val skapi: Skapi,
) {
    private var started = 0
    private var wasInBackground = false

    private val activityCallbacks = object : Application.ActivityLifecycleCallbacks {
        override fun onActivityStarted(activity: Activity) {
            started++
            if (started == 1 && wasInBackground) {
                wasInBackground = false
                skapi.onForeground()
            }
        }

        override fun onActivityStopped(activity: Activity) {
            started = maxOf(0, started - 1)
            if (started == 0 && !activity.isChangingConfigurations) wasInBackground = true
        }

        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
        override fun onActivityResumed(activity: Activity) {}
        override fun onActivityPaused(activity: Activity) {}
        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
        override fun onActivityDestroyed(activity: Activity) {}
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        private var first = true

        override fun onAvailable(network: Network) {
            // the first call only reports the network that was already up when watching started
            if (first) {
                first = false
                return
            }
            skapi.onNetworkAvailable()
        }

        override fun onLost(network: Network) {
            first = false
        }
    }

    private fun start() {
        application.registerActivityLifecycleCallbacks(activityCallbacks)
        try {
            val cm = application.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.registerDefaultNetworkCallback(networkCallback)
        } catch (e: SecurityException) {
            // no ACCESS_NETWORK_STATE permission: only the foreground check runs
        }
    }

    /** Stops watching. */
    public fun stop() {
        application.unregisterActivityLifecycleCallbacks(activityCallbacks)
        try {
            val cm = application.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.unregisterNetworkCallback(networkCallback)
        } catch (e: Exception) {
        }
    }

    public companion object {
        /** Starts watching the app's lifecycle and network for `skapi`. Call once, from Application.onCreate(). */
        @JvmStatic
        public fun watch(application: Application, skapi: Skapi): SkapiLifecycle =
            SkapiLifecycle(application, skapi).also { it.start() }
    }
}
