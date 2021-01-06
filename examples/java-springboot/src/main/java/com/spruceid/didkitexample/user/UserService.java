package com.spruceid.didkitexample.user;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.spruceid.DIDKit;
import com.spruceid.DIDKitException;
import com.spruceid.didkitexample.entity.User;
import com.spruceid.didkitexample.entity.UserCredential;
import com.spruceid.didkitexample.util.DIDKitOptions;
import lombok.AllArgsConstructor;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.text.MessageFormat;
import java.util.Optional;

@Service
@AllArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        final Optional<User> userOptional = userRepository.findByUsername(username);
        return userOptional.orElseThrow(() -> new UsernameNotFoundException(MessageFormat.format("User {0} cannot be found.", username)));
    }

    public void signUp(User user) {
        final String encryptedPassword = bCryptPasswordEncoder.encode(user.getPassword());
        user.setPassword(encryptedPassword);
        user.setEnabled(true);
        userRepository.save(user);
    }

    public String issueCredential(String id, User user) throws DIDKitException, IOException {
        final Resource keyFile = new FileSystemResource("./key.jwk");

        final String key = Files.readString(keyFile.getFile().toPath());
        final String didKey = DIDKit.keyToDID("key", key);
        final String verificationMethod = DIDKit.keyToVerificationMethod("key", key);

        final UserCredential credential = new UserCredential(didKey, id, user.getUsername());
        final DIDKitOptions options = new DIDKitOptions("assertionMethod", verificationMethod, null, null);

        final ObjectMapper mapper = new ObjectMapper();
        final String credentialJson = mapper.writeValueAsString(credential);
        final String optionsJson = mapper.writeValueAsString(options);

        return DIDKit.issueCredential(credentialJson, optionsJson, key);
    }

}

