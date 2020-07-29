package br.com.alura.forum.config.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import br.com.alura.forum.modelo.Usuario;
import br.com.alura.forum.repository.UserRepository;


public class AutenticacaoViaTokenFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final UserRepository userRepository;

    public AutenticacaoViaTokenFilter(TokenService tokenService, UserRepository userRepository) {
        this.tokenService = tokenService;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        Optional<String> token = recuperarToken(httpServletRequest);

        if (token.isPresent() && tokenService.isTokenValido(token.get())) {
            autenticarCliente(token.get());
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private void autenticarCliente(String token) {
        final Long idUsuario = tokenService.getIdUsuario(token);

        final Usuario usuario = userRepository.findById(idUsuario).get();

        final UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private Optional<String> recuperarToken(HttpServletRequest httpServletRequest) {
        final String token = httpServletRequest.getHeader("Authorization");
        if (token == null || token.isEmpty() || !token.startsWith("Bearer ")) {
            return Optional.empty();
        }

        return Optional.of(token.substring(7));
    }
}
