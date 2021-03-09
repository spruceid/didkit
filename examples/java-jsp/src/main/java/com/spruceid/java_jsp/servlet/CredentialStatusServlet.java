package com.spruceid.java_jsp.servlet;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.spruceid.DIDKit;
import com.spruceid.DIDKitException;
import com.spruceid.java_jsp.Utils;
import com.spruceid.java_jsp.model.*;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;

@WebServlet(name = "credentialStatus", value = "/credential/status")
public class CredentialStatusServlet extends HttpServlet {
    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
        final String did = req.getParameter("did");
        final String status = req.getParameter("status");

        final HttpSession session = req.getSession();
        final String username = (String) session.getAttribute("user");

        if (username == null) {
            res.sendError(403);
            return;
        }

        try {
            final String key = (String) req.getServletContext().getAttribute("key");
            final String issuer = DIDKit.keyToDID("key", key);
            final String verificationMethod = DIDKit.keyToVerificationMethod("key", key);

            final Subject subject = new StatusSubject(did, status);
            final Credential credential = new Credential(issuer, subject);

            final Options options = new Options();
            options.setProofPurpose("assertionMethod");
            options.setVerificationMethod(verificationMethod);

            final String vc = Utils.issueCredential(credential, options, key);

            req.getSession().setAttribute("vc", vc);
            res.sendRedirect("display.jsp");
        } catch (Exception e) {
            System.err.println(e.getMessage());
            res.sendError(500);
        }
    }
}
