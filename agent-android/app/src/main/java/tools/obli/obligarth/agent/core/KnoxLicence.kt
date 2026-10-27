package tools.obli.obligarth.agent.core

/**
 * The decisions of the Knox licence (spec §3.2 knox_state, §8.3, §8.5), pure:
 * KnoxBridge reads and writes its preferences, this decides (JVM tests T327).
 *
 * - The probe (a licensed call that works) is the only proof of a licence, and
 *   only once this agent has sent a key: some Knox versions answer the probe
 *   without any licence, and a licence is bound to the package that activated it.
 * - A status broadcast is never a proof: the receiver is exported (anyone may
 *   send one), and the key goes to two managers (KPE, then the backwards-
 *   compatible ELM) that answer each with their own status. A status is taken
 *   only in the window after a sending of this agent; a success of one manager
 *   stays for the key, the refusal of the other does not undo it. A refusal
 *   gives license_error only when the probe fails too.
 * - A key refused (or never answered) is sent again after [RETRY_AFTER_SECONDS]
 *   while the device is not licensed (a passing failure: the Knox servers out of
 *   reach, Q6), never in a loop.
 */
object KnoxLicence {
    const val ABSENT = "absent"
    const val PRESENT = "present"
    const val LICENSED = "licensed"
    const val LICENSE_ERROR = "license_error"

    const val SUCCESS = "success"
    const val FAIL = "fail"

    /** How long after a sending a status broadcast is taken (the activation goes through the Knox servers). */
    const val STATUS_WINDOW_SECONDS = 3_600L

    /** How long after a refused sending the key is sent again. */
    const val RETRY_AFTER_SECONDS = 6 * 3_600L

    /** knox_state. [probe] is called only when a key was sent ([keySha] not null). */
    fun state(present: Boolean, keySha: String?, status: String?, probe: () -> Boolean): String {
        if (!present) return ABSENT
        if (keySha == null) return PRESENT
        if (probe()) return LICENSED
        return if (status == FAIL) LICENSE_ERROR else PRESENT
    }

    /**
     * The status to store after a broadcast, null to ignore it: nothing sent, out of
     * the window after the sending (a clock set back counts as out of it), or a
     * refusal after a success of the same key.
     */
    fun nextStatus(keySha: String?, sentAt: Long, now: Long, stored: String?, success: Boolean): String? {
        if (keySha == null || sentAt <= 0L || now < sentAt || now - sentAt > STATUS_WINDOW_SECONDS) return null
        if (success) return SUCCESS
        return if (stored == SUCCESS) null else FAIL
    }

    /**
     * Whether to send [keySha] (the tenant's key): never sent, another key, or, not
     * [licensed] (asked only then) and no success taken for it (a refusal, or no status at all), a
     * sending older than [RETRY_AFTER_SECONDS] (a clock set back counts as due).
     */
    fun activationDue(keySha: String, sentSha: String?, status: String?, sentAt: Long, now: Long, licensed: () -> Boolean): Boolean {
        if (sentSha != keySha) return true
        if (status == SUCCESS || licensed()) return false
        return now < sentAt || now - sentAt >= RETRY_AFTER_SECONDS
    }
}
