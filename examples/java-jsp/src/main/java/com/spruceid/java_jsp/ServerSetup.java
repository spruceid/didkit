package com.spruceid.java_jsp;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class ServerSetup implements ServletContextListener {
    private static final String create = "create table if not exists users (id integer primary key autoincrement, username string, password string)";
    private Connection connection = null;

    private void initializeKey(ServletContextEvent sce) throws Exception {
        final Path file = Paths.get("/opt/tomcat/data/key.jwk");
        Utils.createKeyIfNotExists(file);
        final String key = Utils.loadKey(file);
        sce.getServletContext().setAttribute("key", key);
    }

    private void initializeDatabase(ServletContextEvent sce) throws Exception {
        Class.forName("org.sqlite.JDBC");
        connection = DriverManager.getConnection("jdbc:sqlite:/opt/tomcat/data/users.db");
        sce.getServletContext().setAttribute("db", connection);

        final PreparedStatement statement = connection.prepareStatement(create);
        statement.setQueryTimeout(5);
        statement.execute();
    }

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        try {
            initializeKey(sce);
            initializeDatabase(sce);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        try {
            if (connection != null)
                connection.close();
        } catch (SQLException e) {
            System.err.println(e.getMessage());
        }
    }
}
