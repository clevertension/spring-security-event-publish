package demo.event.publish;

import demo.event.publish.authentication.UserNameCheckProvider;
import demo.event.publish.exception.AuthenticationFailureUserNameForbiddenEvent;
import demo.event.publish.exception.UserNameForbiddenException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authentication.event.LoggerListener;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.Arrays;
import java.util.Properties;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	ObjectPostProcessor<Object> objectPostProcessor;

	@Bean
    public ApplicationListener loggerListener() {
	    return new LoggerListener();
    }
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		DefaultAuthenticationEventPublisher eventPublisher = objectPostProcessor
				.postProcess(new DefaultAuthenticationEventPublisher());
		Properties mappingProperties = new Properties();
		mappingProperties.put(UserNameForbiddenException.class.getName(), AuthenticationFailureUserNameForbiddenEvent.class.getName());
		eventPublisher.setAdditionalExceptionMappings(mappingProperties);

		http.setSharedObject(AuthenticationManagerBuilder.class, authenticationManagerBuilder(eventPublisher));

		http.authorizeRequests().antMatchers("/", "/home").permitAll().anyRequest().authenticated().and().formLogin()
				.loginPage("/login").loginProcessingUrl("/submitLogin").permitAll().and().logout().permitAll();
	}

	public UserDetailsService userDetailsService() {
		UserDetails user = User.withDefaultPasswordEncoder().username("user").password("password").roles("USER")
				.build();

		return new InMemoryUserDetailsManager(user);
	}

	public AuthenticationManagerBuilder authenticationManagerBuilder(DefaultAuthenticationEventPublisher publisher) {
		AuthenticationManagerBuilder builder = new AuthenticationManagerBuilder(objectPostProcessor);

		ProviderManager parent = new ProviderManager(
                Arrays.asList(new UserNameCheckProvider()),
                null);
		parent.setAuthenticationEventPublisher(publisher);
		builder.parentAuthenticationManager(parent);
		builder.authenticationEventPublisher(publisher);

		builder.authenticationProvider(createDaoAuthenticationProvider());

        return builder;
	}

	private DaoAuthenticationProvider createDaoAuthenticationProvider() {
        DaoAuthenticationProvider p = new DaoAuthenticationProvider();
        p.setUserDetailsService(userDetailsService());
        return p;
    }
}