package com.innernetwork.crm.auth;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.innernetwork.crm.auth.AuthExceptions.TooManyAttemptsException;
import com.innernetwork.crm.config.CrmProperties;

import org.springframework.stereotype.Component;

/**
 * Slows down password guessing and mass signups.
 *
 * <p>Counts failed logins per account and per IP address, and signups per IP address, in a fixed
 * window. Counters live in memory, which is enough for one app server; with several servers they
 * move to Redis.
 */
@Component
class LoginRateLimiter {

	private final Cache<String, AtomicInteger> counters;

	private final int maxFailuresPerAccount;

	private final int maxFailuresPerIp;

	private final Duration window;

	LoginRateLimiter(CrmProperties properties) {
		CrmProperties.LoginRateLimit config = properties.loginRateLimit();
		this.maxFailuresPerAccount = config.maxFailuresPerAccount();
		this.maxFailuresPerIp = config.maxFailuresPerIp();
		this.window = config.window();
		this.counters = Caffeine.newBuilder().expireAfterWrite(this.window).maximumSize(100_000).build();
	}

	void checkLoginAllowed(String ip, String email) {
		if (count(accountKey(email)) >= this.maxFailuresPerAccount || count(ipKey(ip)) >= this.maxFailuresPerIp) {
			throw new TooManyAttemptsException(this.window);
		}
	}

	void recordLoginFailure(String ip, String email) {
		increment(accountKey(email));
		increment(ipKey(ip));
	}

	void recordLoginSuccess(String email) {
		this.counters.invalidate(accountKey(email));
	}

	/** Counts every signup attempt, successful or not. */
	void checkAndRecordSignup(String ip) {
		if (increment("signup:" + ip) > this.maxFailuresPerIp) {
			throw new TooManyAttemptsException(this.window);
		}
	}

	private int count(String key) {
		AtomicInteger counter = this.counters.getIfPresent(key);
		return (counter != null) ? counter.get() : 0;
	}

	private int increment(String key) {
		return this.counters.get(key, k -> new AtomicInteger()).incrementAndGet();
	}

	private static String accountKey(String email) {
		return "account:" + email;
	}

	private static String ipKey(String ip) {
		return "ip:" + ip;
	}

}
