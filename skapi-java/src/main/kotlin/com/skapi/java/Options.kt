package com.skapi.java

import com.skapi.DeviceKeyStore
import com.skapi.EncryptionOptions
import com.skapi.FetchOptions

/**
 * FetchOptions for Java, one setting at a time:
 * `new FetchOptionsBuilder().limit(20).ascending(false).build()`.
 *
 * limit: how many items per page (up to 1000; the server's default is 50).
 * ascending: the sort direction.
 * startKey: where to start: the "startKey" of an earlier answer (a Map or a String), "start" to start
 *   over, or "end".
 * fetchMore: true reads the next page of the same query, continuing from the last answer.
 */
public class FetchOptionsBuilder {
    private var limit: Int? = null
    private var ascending: Boolean? = null
    private var startKey: Any? = null
    private var fetchMore: Boolean = false

    public fun limit(limit: Int): FetchOptionsBuilder = apply { this.limit = limit }

    public fun ascending(ascending: Boolean): FetchOptionsBuilder = apply { this.ascending = ascending }

    public fun startKey(startKey: Any?): FetchOptionsBuilder = apply { this.startKey = startKey }

    public fun fetchMore(fetchMore: Boolean): FetchOptionsBuilder = apply { this.fetchMore = fetchMore }

    public fun build(): FetchOptions =
        FetchOptions(limit, ascending, startKey?.let { SkapiJson.fromJava(it) }, fetchMore)
}

/**
 * EncryptionOptions for Java, starting from the defaults:
 * `new EncryptionOptionsBuilder().withheld("sentinel").deviceKeyStore(store).build()`.
 * Each setting means what it means in EncryptionOptions.
 */
public class EncryptionOptionsBuilder {
    private val defaults = EncryptionOptions()
    private var iterations: Int = defaults.iterations
    private var trustPolicy: String = defaults.trustPolicy
    private var withheld: String = defaults.withheld
    private var recovery: String = defaults.recovery
    private var table: String = defaults.table
    private var persistDevice: Boolean = defaults.persistDevice
    private var deviceKeyStore: DeviceKeyStore? = defaults.deviceKeyStore

    /** PBKDF2 rounds for the password wrap (at least 100000). */
    public fun iterations(iterations: Int): EncryptionOptionsBuilder = apply { this.iterations = iterations }

    /** "tofu" (default) or "strict". */
    public fun trustPolicy(trustPolicy: String): EncryptionOptionsBuilder = apply { this.trustPolicy = trustPolicy }

    /** "null" (default) or "sentinel". */
    public fun withheld(withheld: String): EncryptionOptionsBuilder = apply { this.withheld = withheld }

    /** "code" (default) or "none". */
    public fun recovery(recovery: String): EncryptionOptionsBuilder = apply { this.recovery = recovery }

    /** The keyring table. */
    public fun table(table: String): EncryptionOptionsBuilder = apply { this.table = table }

    public fun persistDevice(persistDevice: Boolean): EncryptionOptionsBuilder = apply { this.persistDevice = persistDevice }

    /** Where to keep the master key; skapi-android has AndroidKeystoreDeviceKeyStore. */
    public fun deviceKeyStore(deviceKeyStore: DeviceKeyStore?): EncryptionOptionsBuilder = apply { this.deviceKeyStore = deviceKeyStore }

    public fun build(): EncryptionOptions =
        EncryptionOptions(iterations, trustPolicy, withheld, recovery, table, persistDevice, deviceKeyStore)
}
