package com.spruceid.java_jsp.servlet;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(name = "signOut", value = "/sign-out")
public class SignOutServlet extends HttpServlet {

    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
        req.getSession().removeAttribute("user");
        res.sendRedirect("index.jsp");
    }
}
