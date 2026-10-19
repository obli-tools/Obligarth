package tools.obli.obligarth.agent.core

/** Enrollment phases of the agent. */
enum class Phase {
    /** No configuration. */
    NEW,
    /** Configuration accepted, enrollment pending (or retrying after a network failure). */
    CONFIGURED,
    /** Enrolled: agentId and pinned server keys known. */
    ENROLLED,
    /** 403 tokenInvalid: waits for a new configuration. */
    TOKEN_REJECTED,
    /** Signed 403 agentRevoked: key and configuration erased; a new configuration is accepted. */
    REVOKED,
}

sealed class EnrollEvent {
    /** A configuration arrived (intent, file or typed). */
    data class ConfigImported(val valid: Boolean) : EnrollEvent()
    object EnrollSucceeded : EnrollEvent()
    object TokenRejected : EnrollEvent()
    /** A transient failure (network, 5xx, 429, unsigned answer): the configuration is kept. */
    object EnrollFailed : EnrollEvent()
    /** 403 agentRevoked whose server signature verified (RS-8). */
    object RevokedSigned : EnrollEvent()
    /** Any unsigned or badly signed answer: never a destructive transition. */
    object UnsignedAnswer : EnrollEvent()
}

/** Outcome of an event: the next phase and whether the configuration is taken. */
data class Transition(val next: Phase, val acceptConfig: Boolean = false, val eraseIdentity: Boolean = false, val refusal: String? = null)

/**
 * The enrollment state machine (spec §4.9, §4.8, RS-8). Pure: the caller
 * persists the result.
 */
object EnrollmentMachine {
    fun acceptsConfig(phase: Phase): Boolean = phase != Phase.ENROLLED

    fun next(phase: Phase, event: EnrollEvent): Transition = when (event) {
        is EnrollEvent.ConfigImported -> when {
            // Refused once enrolled, by every path, unless after a signed agentRevoked (§4.9).
            phase == Phase.ENROLLED -> Transition(phase, refusal = "already_enrolled")
            !event.valid -> Transition(phase, refusal = "invalid")
            else -> Transition(Phase.CONFIGURED, acceptConfig = true)
        }
        EnrollEvent.EnrollSucceeded ->
            if (phase == Phase.CONFIGURED) Transition(Phase.ENROLLED) else Transition(phase, refusal = "not_configured")
        EnrollEvent.TokenRejected ->
            if (phase == Phase.CONFIGURED) Transition(Phase.TOKEN_REJECTED) else Transition(phase)
        EnrollEvent.EnrollFailed -> Transition(phase)
        EnrollEvent.RevokedSigned ->
            if (phase == Phase.ENROLLED) Transition(Phase.REVOKED, eraseIdentity = true) else Transition(phase)
        EnrollEvent.UnsignedAnswer -> Transition(phase)
    }
}
