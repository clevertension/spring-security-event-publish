package demo.event.publish.exception;

import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class AuthenticationFailureUserNameForbiddenEvent extends AbstractAuthenticationFailureEvent {

	public AuthenticationFailureUserNameForbiddenEvent(Authentication authentication,
                                                       AuthenticationException exception) {
		super(authentication, exception);
	}
}
