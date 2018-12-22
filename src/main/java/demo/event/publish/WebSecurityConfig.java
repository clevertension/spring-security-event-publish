package demo.event.publish;

import java.util.Arrays;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import demo.event.publish.authentication.UserNameCheckProvider;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers("/", "/home").permitAll().anyRequest().authenticated().and().formLogin()
				.loginPage("/login").loginProcessingUrl("/submitLogin").permitAll().and().logout().permitAll();
	}

	@Bean
	@Override
	public UserDetailsService userDetailsService() {
		UserDetails user = User.withDefaultPasswordEncoder().username("user").password("password").roles("USER")
				.build();

		return new InMemoryUserDetailsManager(user);
	}
	
	@Bean
	public AuthenticationManager authenticationManager(ApplicationEventPublisher publisher) {
		ProviderManager parent = new ProviderManager(
                Arrays.asList(new UserNameCheckProvider()),
                null);
        ProviderManager mgr = new ProviderManager(
                Arrays.asList(new DaoAuthenticationProvider()),
                parent);

        AuthenticationEventPublisher myPublisher = new DefaultAuthenticationEventPublisher(publisher);
        mgr.setAuthenticationEventPublisher(myPublisher);
        parent.setAuthenticationEventPublisher(myPublisher);
        return mgr;
	}
}