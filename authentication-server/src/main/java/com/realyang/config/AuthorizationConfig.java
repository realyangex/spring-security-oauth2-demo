package com.realyang.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * @author realyangex@126.com
 * @date 2021/9/14 16:20
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationConfig extends AuthorizationServerConfigurerAdapter {


    public static final String CLIEN_ID = "c1";
    public static final String CLIENT_SECRET = "secret";

    public static final String GRANT_TYPE_PASSWORD = "password";
    public static final String AUTHORIZATION_CODE = "authorization_code";
    public static final String CLIENT_CREDENTIALS = "client_credentials";
    public static final String IMPLICIT = "implicit";

    public static final String SCOPE_All = "all";
    public static final String SCOPE_READ = "read";
    public static final String SCOPE_WRITE = "write";
    public static final String TRUST = "trust";

    public static final int ACCESS_TOKEN_VALIDITY_SECONDS = 1 * 60 * 60;
    public static final int FREFRESH_TOKEN_VALIDITY_SECONDS = 6 * 60 * 60;

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private AuthorizationCodeServices authorizationCodeServices;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private ClientDetailsService clientDetailsService;

    /**
     * 3.?????????????????????????????????
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                // oauth/token_key??????
                .tokenKeyAccess("permitAll()")
                // oauth/check_token??????
                .checkTokenAccess("permitAll()")
                // ???????????????????????????
                .allowFormAuthenticationForClients();

    }

    /**
     * 1.???????????????
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient(CLIEN_ID)
                //?????????ID
                .secret(new BCryptPasswordEncoder().encode(CLIENT_SECRET))
                .authorizedGrantTypes(GRANT_TYPE_PASSWORD, AUTHORIZATION_CODE, CLIENT_CREDENTIALS, IMPLICIT)
                .scopes(SCOPE_READ, SCOPE_WRITE, TRUST, SCOPE_All)
                .accessTokenValiditySeconds(ACCESS_TOKEN_VALIDITY_SECONDS)
                .autoApprove(false)
                .redirectUris("http://www.baidu.com")
                .refreshTokenValiditySeconds(FREFRESH_TOKEN_VALIDITY_SECONDS);
    }

    /**
     * 2.??????????????????
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints)
            throws Exception {
        endpoints
                //??????????????? ?????????
                .pathMapping("/oauth/confirm_access", "/customer/confirm_access")
                //???????????????
                .authenticationManager(authenticationManager)
                //?????????????????????????????????
                .userDetailsService(userDetailsService)
                //???????????????
                .authorizationCodeServices(authorizationCodeServices)
                //??????????????????
                .tokenServices(tokenService())
                .allowedTokenEndpointRequestMethods(HttpMethod.POST);
    }

    public AuthorizationServerTokenServices tokenService() {
        DefaultTokenServices service = new DefaultTokenServices();
        //?????????????????????
        service.setClientDetailsService(clientDetailsService);
        //????????????????????????
        service.setSupportRefreshToken(true);
        //??????????????????-??????
        service.setTokenStore(tokenStore);
        // ?????????????????????2??????
        service.setAccessTokenValiditySeconds(7200);
        // ???????????????????????????3???
        service.setRefreshTokenValiditySeconds(259200);
        return service;
    }

    /**
     * ????????????????????????????????????????????????????????????????????????
     */
    @Bean
    public AuthorizationCodeServices authorizationCodeServices() {
        return new InMemoryAuthorizationCodeServices();
    }
}
