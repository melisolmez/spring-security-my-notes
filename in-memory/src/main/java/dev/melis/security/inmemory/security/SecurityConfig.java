package dev.melis.security.inmemory.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // security filther chain uygulamak için kullanılır
@EnableMethodSecurity // controller sınıfı verilirse oradaki metodların securitysi için
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder  passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /*
    uygulamanızdaki kullanıcı detaylarını bellekte tutmak ve bu detaylara erişim sağlamak için bir UserDetailsService oluşturur.
     Bu detaylar, örnek olarak InMemoryUserDetailsManager ile sağlanır,
     yani kullanıcı adları, şifreler ve roller bellekte saklanır.
     */

    @Bean
    public UserDetailsService users(){
        UserDetails user1= User.builder()
                .username("melis")
                .password(passwordEncoder().encode("1234"))
                .roles("USER")
                .build();

        UserDetails admin=User.builder()
                .username("melo")
                .password(passwordEncoder().encode("1907"))
                .roles("ADMİN")
                .build();

        return new InMemoryUserDetailsManager(user1,admin);
    }
    /*
        - authorizeHttpRequests(x->x.requestMatchers("/public/**","/auth/**").permitAll()): public ile başlayan tüm end pointler
        ve auth ile başlayan bütün end pointleri geçmesine izin ver yani bir kimlik doğrulaması olmayacak
        - authorizeHttpRequests(x->x.anyRequest().authenticated()) : gelen herhangi bir isteği gizle ve kimlik doğrulamasına tabi tut
        bu en altta olsun
        - authorizeHttpRequests(x->x.requestMatchers("/private/user/**").hasRole("USER")) rolü user olanlar
        private/user endpointleri altındakilerine ulaşabilir yani aslında tek tek metodlara  @PreAuthorize("hasRole('USER')") bunu yazmak yerine
        buraya tanımlanır.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity security) throws Exception {
        security
                .headers(x->x.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(x->x.requestMatchers("/public/**","/auth/**").permitAll())
                .authorizeHttpRequests(x->x.requestMatchers("/private/user/**").hasRole("USER"))
                .authorizeHttpRequests(x->x.requestMatchers("/private/admin/**").hasRole("ADMİN"))
                .authorizeHttpRequests(x->x.anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults());

        return security.build();
    }
}
