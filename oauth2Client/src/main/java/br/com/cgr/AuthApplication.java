package br.com.cgr;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CompositeFilter;

@SpringBootApplication
@EnableOAuth2Client
@RestController
public class AuthApplication extends WebSecurityConfigurerAdapter {

	@Autowired
	private OAuth2ClientContext oauth2ClientContext;

	public static void main(String[] args) {
		SpringApplication.run(AuthApplication.class, args);
	}

	@RequestMapping({"/user", "/me"})
	public Principal user(Principal principal) {
		return principal;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//@formatter:off
		http.antMatcher("/**")
			.authorizeRequests().antMatchers("/", "/login", "/webjars/**").permitAll()
			.anyRequest().authenticated()
			.and().exceptionHandling().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/"))
			.and().logout().logoutSuccessUrl("/")
			.and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
			.and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
		//@formatter:on
	}

	private Filter ssoFilter() {
		CompositeFilter filter = new CompositeFilter();
		List<Filter> filters = new ArrayList<Filter>(3);
		filters.add(ssoFilter("/login/facebook", facebook()));
		filters.add(ssoFilter("/login/github", github()));
		filters.add(ssoFilter("/login/acme", acme()));

		filter.setFilters(filters);

		return filter;
	}

	private OAuth2ClientAuthenticationProcessingFilter ssoFilter(String stringLogin, PartialResource clientRes) {
		OAuth2ClientAuthenticationProcessingFilter oa2Filter = new OAuth2ClientAuthenticationProcessingFilter(
				stringLogin);
		OAuth2RestTemplate oa2Template = new OAuth2RestTemplate(clientRes.getClient(), oauth2ClientContext);
		oa2Filter.setRestTemplate(oa2Template);
		oa2Filter.setTokenServices(new UserInfoTokenServices(clientRes.getResource().getUserInfoUri(),
				clientRes.getClient().getClientId()));
		return oa2Filter;
	}

	@Bean
	@ConfigurationProperties("facebook")
	public PartialResource facebook() {
		return new PartialResource();
	}

	@Bean
	@ConfigurationProperties("github")
	public PartialResource github() {
		return new PartialResource();
	}

	@Bean
	@ConfigurationProperties("acme")
	public PartialResource acme() {
		return new PartialResource();
	}

	@Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(filter);
		registration.setOrder(-100);
		return registration;
	}

}