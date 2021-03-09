package com.spruceid.java_jsp.servlet;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.spruceid.DIDKit;
import com.spruceid.java_jsp.model.Options;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.List;
import java.util.Map;

@WebServlet(name = "signInVerifiablePresentation", value = "/sign-in/verifiable-presentation")
public class SignInVerifiablePresentationServlet extends HttpServlet {
    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
        final TypeReference type = new TypeReference<Map<String, Object>>() {
        };

        final String vp = req.getParameter("verifiable-presentation");

        final ObjectMapper mapper = new ObjectMapper();

        final Map<String, Object> presentation = (Map<String, Object>) mapper.readValue(vp, type);

        try {
            final Options options = new Options();
            options.setProofPurpose("authentication");

            final String optionsStr = mapper.writeValueAsString(options);

            final String result = DIDKit.verifyPresentation(vp, optionsStr);
            final Map<String, Object> resultMap = (Map<String, Object>) mapper.readValue(result, type);

            if (((List<String>) resultMap.get("errors")).size() > 0) {
                System.err.println("[ERROR] VP: " + resultMap.get("errors"));
                res.sendError(400);
            }
        } catch (Exception e) {
            System.err.println("[ERROR] VP: " + e.getMessage());
            res.sendError(500);
        }

        final Object vcs = presentation.get("verifiableCredential");
        final Map<String, Object> vc = (Map<String, Object>) (vcs instanceof Object[] ? ((Object[]) vcs)[0] : vcs);

        try {
            final Options options = new Options();
            options.setProofPurpose("authentication");

            final String vcStr = mapper.writeValueAsString(vc);
            final String optionsStr = mapper.writeValueAsString(options);

            final String result = DIDKit.verifyCredential(vcStr, optionsStr);
            final Map<String, Object> resultMap = (Map<String, Object>) mapper.readValue(result, type);

            if (((List<String>) resultMap.get("errors")).size() > 0) {
                System.err.println("[ERROR] VC: " + resultMap.get("errors"));
                res.sendError(400);
            }
        } catch (Exception e) {
            System.err.println("[ERROR] VC: " + e.getMessage());
            res.sendError(500);
        }

        final Map<String, Object> credentialSubject = (Map<String, Object>) vc.get("credentialSubject");
        final String username = credentialSubject.get("username").toString();
        final HttpSession session = req.getSession();
        session.setAttribute("user", username);
        res.sendRedirect("../index.jsp");
    }
}
