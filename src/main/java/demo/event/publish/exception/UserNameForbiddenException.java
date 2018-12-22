package demo.event.publish.exception;

import org.springframework.security.core.AuthenticationException;

public class UserNameForbiddenException extends AuthenticationException {

	public UserNameForbiddenException(String msg) {
		super(msg);
	}

	public UserNameForbiddenException(String msg, Throwable t) {
		super(msg, t);
	}

}
