package com.realyang.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

/**
 * @author realyangex@126.com
 * @date 2021/9/22 17:27
 */
@Configuration
public class TokenConfig {
    @Bean
    public TokenStore tokenStore() {
        //使用基于内存的普通令牌
        return new InMemoryTokenStore();
    }

}
