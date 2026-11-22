package com.innernetwork.crm.auth;

import java.time.Duration;

/** Errors of the auth flow. Their messages are deliberately generic: they never say which part was wrong. */
public final class AuthExceptions {

	private AuthExceptions() {
	}

	/** Wrong e-mail, wrong password or disabled account: all look the same to the caller. */
	public static class InvalidCredentialsException extends RuntimeException {
	}

	/** Missing, unknown, expired, revoked or reused refresh token. */
	public static class InvalidRefreshTokenException extends RuntimeException {
	}

	/** The account could not be created (for example, the e-mail is already used). */
	public static class AccountUnavailableException extends RuntimeException {
	}

	public static class TooManyAttemptsException extends RuntimeException {

		private final Duration retryAfter;

		public TooManyAttemptsException(Duration retryAfter) {
			this.retryAfter = retryAfter;
		}

		public Duration retryAfter() {
			return this.retryAfter;
		}

	}

}
