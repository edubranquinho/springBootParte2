package br.com.alura.forum.config.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

import br.com.alura.forum.modelo.Usuario;
import br.com.alura.forum.repository.UserRepository;

@Service
public class AutenticacaoService implements UserDetailsService {

    private final UserRepository userRepository;

    public AutenticacaoService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        final Optional<Usuario> usuario = userRepository.findByEmail(username);
        return usuario.orElseThrow(() -> new UsernameNotFoundException("Usuário " + username + " inválido"));
    }
}
