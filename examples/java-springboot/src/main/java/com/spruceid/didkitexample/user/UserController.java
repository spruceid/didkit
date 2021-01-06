package com.spruceid.didkitexample.user;

import com.spruceid.didkitexample.entity.user.User;
import com.spruceid.didkitexample.util.QRCode;
import com.spruceid.didkitexample.util.Resources;
import lombok.AllArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.time.Duration;
import java.util.UUID;

@Controller
@AllArgsConstructor
public class UserController {
    private final UserService userService;
    private final StringRedisTemplate redisTemplate;

    @GetMapping("/sign-up")
    String signUpGet(User user) {
        return "sign-up";
    }

    @PostMapping("/sign-up")
    String signUpPost(User user) {
        userService.signUp(user);
        return "redirect:/sign-in";
    }

    @GetMapping("/sign-in")
    ModelAndView signIn() throws Exception {
        final String uuid = UUID.randomUUID().toString();
        final String url = "https://" + Resources.baseUrl + "/verifiable-presentation-request/" + uuid;
        final ModelAndView model = QRCode.getModelAndView("sign-in", url);
        model.addObject("uuid", uuid);
        return model;
    }

    @GetMapping("/credential")
    ModelAndView credential(
            @AuthenticationPrincipal User user
    ) throws Exception {
        final String uuid = UUID.randomUUID().toString();
        redisTemplate.opsForValue().set(uuid, user.getUsername());
        redisTemplate.expire(uuid, Duration.ofSeconds(90));
        final String url = "https://" + Resources.baseUrl + "/credential-offer/" + uuid;
        return QRCode.getModelAndView("credential", url);
    }

    @PostMapping("/credential")
    ModelAndView credentialOffer(
            @AuthenticationPrincipal User user,
            @RequestParam("did") String did,
            ModelAndView model
    ) throws Exception {
        final String credential = userService.issueCredential(did, user);
        model.addObject("credential", credential);
        return model;
    }
}
