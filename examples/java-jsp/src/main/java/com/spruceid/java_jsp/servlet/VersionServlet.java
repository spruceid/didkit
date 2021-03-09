package com.spruceid.java_jsp.servlet;

import com.spruceid.DIDKit;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@WebServlet(name = "version", value = "/version")
public class VersionServlet extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
        res.setContentType("text/plain");
        final PrintWriter out = res.getWriter();
        out.print(DIDKit.getVersion());
    }
}
