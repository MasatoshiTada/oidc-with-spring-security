package com.example.oidcrpsample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private RestTemplateBuilder restTemplateBuilder;

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(
                PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.oauth2Login(oauth2 -> oauth2
                .tokenEndpoint(token -> token
                        // タイムアウト設定済みのDefaultAuthorizationCodeTokenResponseClientを指定
                        .accessTokenResponseClient(accessTokenResponseClient())
                ).userInfoEndpoint(userInfo -> userInfo
                        // タイムアウト設定済みのDefaultOAuth2UserServiceを指定
                        .userService(oAuth2UserService())
                        // タイムアウト設定済みのOidcUserServiceを指定
                        .oidcUserService(oidcUserService())
                ).loginPage("/login")
                .permitAll()
        ).authorizeRequests(auth -> auth
                .anyRequest().authenticated()
        ).logout(logout -> logout
                .logoutSuccessHandler(oidcLogoutSuccessHandler())
        );
    }

    private DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient() {
        RestTemplate restTemplate = restTemplateBuilder
                // タイムアウトを設定
                .setConnectTimeout(Duration.ofMillis(1000))
                .setReadTimeout(Duration.ofMillis(1000))
                // トークンエンドポイントからのレスポンスを解析するためのHttpMessageConverterを設定
                .messageConverters(
                        new FormHttpMessageConverter(),
                        new OAuth2AccessTokenResponseHttpMessageConverter())
                // トークンエンドポイントからのエラーレスポンスを解析するためのErrorHandlerを設定
                .errorHandler(new OAuth2ErrorResponseErrorHandler())
                .build();
        DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient =
                new DefaultAuthorizationCodeTokenResponseClient();
        // タイムアウト設定済みのRestTemplateを設定
        accessTokenResponseClient.setRestOperations(restTemplate);
        return accessTokenResponseClient;
    }

    private DefaultOAuth2UserService oAuth2UserService() {
        RestTemplate restTemplate = restTemplateBuilder
                // タイムアウトを設定
                .setConnectTimeout(Duration.ofMillis(1000))
                .setReadTimeout(Duration.ofMillis(1000))
                // /userinfoなどからのエラーレスポンスを解析するためのErrorHandlerを設定
                .errorHandler(new OAuth2ErrorResponseErrorHandler())
                .build();
        DefaultOAuth2UserService oAuth2UserService = new DefaultOAuth2UserService();
        // タイムアウト設定済みのRestTemplateを設定
        oAuth2UserService.setRestOperations(restTemplate);
        return oAuth2UserService;
    }

    private OidcUserService oidcUserService() {
        OidcUserService oidcUserService = new OidcUserService();
        // タイムアウト設定済みのOAuth2UserServiceを設定
        oidcUserService.setOauth2UserService(oAuth2UserService());
        return oidcUserService;
    }

    private LogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedLogoutSuccessHandler(this.clientRegistrationRepository);
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");
        return oidcLogoutSuccessHandler;
    }
}
