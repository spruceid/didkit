package com.spruceid.java_jsp.servlet;

import at.favre.lib.crypto.bcrypt.BCrypt;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

@WebServlet(name = "signUp", value = "/sign-up")
public class SignUpServlet extends HttpServlet {
    private static final String query = "select 1 from users where username = ?";
    private static final String save = "insert into users(username, password) values (?, ?)";

    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
        final String username = req.getParameter("username");
        final String password = req.getParameter("password");
        final String hash = BCrypt.withDefaults().hashToString(12, password.toCharArray());

        try {
            final Connection connection = (Connection) req.getServletContext().getAttribute("db");

            final PreparedStatement query = connection.prepareStatement(SignUpServlet.query);
            query.setQueryTimeout(5);
            query.setString(1, username);
            final ResultSet resultSet = query.executeQuery();

            if (resultSet.isBeforeFirst()) {
                res.sendError(400);
                return;
            }

            final PreparedStatement save = connection.prepareStatement(SignUpServlet.save);
            save.setQueryTimeout(5);
            save.setString(1, username);
            save.setString(2, hash);
            save.executeUpdate();

            res.sendRedirect("index.jsp");
        } catch (SQLException e) {
            System.err.println(e.getMessage());
            res.sendError(500);
        }
    }
}
