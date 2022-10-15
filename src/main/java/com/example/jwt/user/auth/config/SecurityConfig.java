package com.example.jwt.user.auth.config;



import com.example.jwt.user.application.UserRepository;
import com.example.jwt.user.auth.TokenService;
import com.example.jwt.user.auth.filter.JwtAuthenticationFilter;
import com.example.jwt.user.auth.filter.JwtAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	private final CorsConfig corsConfig;
	private final TokenService tokenService;
	private final UserRepository userRepository;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.addFilter(corsConfig.corsFilter())
				.csrf().disable()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
				.formLogin().disable()
				.httpBasic().disable()
				
				.addFilter(new JwtAuthenticationFilter(authenticationManager(), tokenService))
				.addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository, tokenService))
				.authorizeRequests()
				.antMatchers("/user/**")
				.access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
				.antMatchers("/admin/**")
					.access("hasRole('ROLE_ADMIN')")
				.anyRequest().permitAll();
	}
}




