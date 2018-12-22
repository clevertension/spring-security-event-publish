package demo.event.publish.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import demo.event.publish.exception.UserNameForbiddenException;

public class UserNameCheckProvider implements AuthenticationProvider {

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
	    String userName = (String)authentication.getPrincipal();
	    if (userName.startsWith("fuck")) {
            throw new UserNameForbiddenException("user name is forbidden");
        }
        return authentication;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return true;
	}

}
