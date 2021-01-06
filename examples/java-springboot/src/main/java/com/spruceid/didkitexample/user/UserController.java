package com.spruceid.didkitexample.user;

import com.spruceid.didkitexample.entity.User;
import com.spruceid.didkitexample.util.QRCode;
import lombok.AllArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;
import javax.servlet.http.HttpServletRequest;
import org.springframework.ui.Model;

@Controller
@AllArgsConstructor
public class UserController {
    private final UserService userService;

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
    String signIn() {
        return "sign-in";
    }

    @GetMapping("/credential")
    String credential() {
        return "credential";
    }

    @PostMapping("/credential")
    String credentialOffer(HttpServletRequest request, @AuthenticationPrincipal User user, Model model) throws Exception {
        final String did = request.getParameter("did");
        final String credential = userService.issueCredential(did, user);
        model.addAttribute("credential", credential);
        return "credential-offer";
    }

    @PostMapping("/qrcode")
    ModelAndView qrcode(String id, @AuthenticationPrincipal User user) throws Exception {
        // TODO: [wip] example of how to display the qrcode
        final String credential = userService.issueCredential(id, user);
        return QRCode.getModelAndView(credential);
    }

}
