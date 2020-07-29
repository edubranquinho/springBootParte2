package br.com.alura.forum.config.security;

import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public class AutenticacaoViaTokenFilter extends OncePerRequestFilter {

    private final TokenService tokenService;

    public AutenticacaoViaTokenFilter(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        Optional<String> token = recuperarToken(httpServletRequest);

        boolean tokenEhValido = tokenService.isTokenValido(token.get());

        System.out.println(tokenEhValido);

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private Optional<String> recuperarToken(HttpServletRequest httpServletRequest) {
        final String token = httpServletRequest.getHeader("Authorization");
        if (token == null || token.isEmpty() || !token.startsWith("Bearer ")) {
            return Optional.empty();
        }

        return Optional.of(token.substring(7));
    }
}
