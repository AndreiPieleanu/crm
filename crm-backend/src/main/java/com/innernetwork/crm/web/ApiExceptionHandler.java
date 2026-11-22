package com.innernetwork.crm.web;

import java.util.List;
import java.util.Map;

import com.innernetwork.crm.auth.AuthExceptions.AccountUnavailableException;
import com.innernetwork.crm.auth.AuthExceptions.InvalidCredentialsException;
import com.innernetwork.crm.auth.AuthExceptions.InvalidRefreshTokenException;
import com.innernetwork.crm.auth.AuthExceptions.TooManyAttemptsException;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * Turns errors into RFC 9457 "problem" responses. Messages are fixed texts: no SQL, stack traces,
 * or internal details ever reach the client.
 */
@RestControllerAdvice
class ApiExceptionHandler extends ResponseEntityExceptionHandler {

	@Override
	protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
			HttpHeaders headers, HttpStatusCode status, WebRequest request) {
		List<Map<String, String>> errors = ex.getBindingResult()
			.getFieldErrors()
			.stream()
			.map(error -> Map.of("field", error.getField(), "message", String.valueOf(error.getDefaultMessage())))
			.toList();
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Some fields are invalid.");
		problem.setProperty("errors", errors);
		return ResponseEntity.badRequest().body(problem);
	}

	@ExceptionHandler(InvalidCredentialsException.class)
	ProblemDetail invalidCredentials() {
		return ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Invalid e-mail or password.");
	}

	@ExceptionHandler(InvalidRefreshTokenException.class)
	ProblemDetail invalidRefreshToken() {
		return ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Your session has expired. Please log in again.");
	}

	@ExceptionHandler(TooManyAttemptsException.class)
	ResponseEntity<ProblemDetail> tooManyAttempts(TooManyAttemptsException ex) {
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.TOO_MANY_REQUESTS,
				"Too many attempts. Please try again later.");
		return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
			.header(HttpHeaders.RETRY_AFTER, String.valueOf(ex.retryAfter().toSeconds()))
			.body(problem);
	}

	@ExceptionHandler(AccountUnavailableException.class)
	ProblemDetail accountUnavailable() {
		return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT,
				"An account cannot be created with these details.");
	}

	@ExceptionHandler(NotFoundException.class)
	ProblemDetail notFound() {
		return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, "Not found.");
	}

	@ExceptionHandler(DataIntegrityViolationException.class)
	ProblemDetail dataIntegrityViolation() {
		return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, "The request conflicts with existing data.");
	}

}
