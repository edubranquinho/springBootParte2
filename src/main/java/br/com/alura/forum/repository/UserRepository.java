package br.com.alura.forum.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

import br.com.alura.forum.modelo.Usuario;

public interface UserRepository extends JpaRepository<Usuario, Long> {

    Optional<Usuario> findByEmail(String email);

}
