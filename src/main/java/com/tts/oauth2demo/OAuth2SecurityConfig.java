package com.tts.oauth2demo;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity //marks that this is the class that configures the security
public class OAuth2SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.authorizeRequests()
			.antMatchers("/", "/error", "/webjars/**").permitAll()
			.anyRequest().authenticated()
			.and()
				.exceptionHandling()
					.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
		
		http.oauth2Login().defaultSuccessUrl("/", true)
		.and()
			.logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
			.logoutSuccessUrl("/").deleteCookies("JSESSIONID")
			.invalidateHttpSession(true);
	
	//AuthenticationFailureHandler
		http.oauth2Login(o -> o
	            .failureHandler((request, response, exception) -> {
				    request.getSession().setAttribute("error.message", exception.getMessage());
			    handler.onAuthenticationFailure(request, response, exception);
	            })
	        );
	
	}

}
