package com.spruceid.java_jsp.servlet;

import at.favre.lib.crypto.bcrypt.BCrypt;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

@WebServlet(name = "signInUsernamePassword", value = "/sign-in/user-password")
public class SignInUsernamePasswordServlet extends HttpServlet {
    private static final String query = "select password from users where username = ?";

    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
        final String username = req.getParameter("username");
        final String password = req.getParameter("password");

        try {
            final Connection connection = (Connection) req.getServletContext().getAttribute("db");

            final PreparedStatement query = connection.prepareStatement(SignInUsernamePasswordServlet.query);
            query.setQueryTimeout(5);
            query.setString(1, username);
            final ResultSet resultSet = query.executeQuery();

            if (!resultSet.isBeforeFirst()) {
                res.sendError(401);
                return;
            }

            final String hash = resultSet.getString(1);
            final BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), hash.toCharArray());
            if (result.verified) {
                final HttpSession session = req.getSession();
                session.setAttribute("user", username);
                res.sendRedirect("../index.jsp");
            } else {
                res.sendError(401);
            }
        } catch (SQLException e) {
            System.err.println(e.getMessage());
            res.sendError(500);
        }
    }
}
