package com.example;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mindrot.jbcrypt.BCrypt;
import org.apache.commons.text.StringEscapeUtils;

public class OwaspExamples {
    private static final Logger logger = LogManager.getLogger(OwaspExamples.class);

    public static void main(String[] args) {
        // Logging Example
        logger.info("Running OWASP examples...");

        // Input validation example
        String userInputAge = "25";
        try {
            int age = Integer.parseInt(userInputAge);
            if (age < 0 || age > 150) {
                throw new NumberFormatException();
            }
            System.out.println("Valid age input: " + age);
        } catch (NumberFormatException e) {
            System.out.println("Invalid age input.");
        }

        // Hashing password example
        String userPassword = "my_secure_password";
        String hashedPassword = BCrypt.hashpw(userPassword, BCrypt.gensalt());
        System.out.println("Hashed password: " + hashedPassword);

        // Check password
        String userInputPassword = "my_secure_password";
        if (BCrypt.checkpw(userInputPassword, hashedPassword)) {
            System.out.println("Authentication successful.");
        } else {
            System.out.println("Authentication failed.");
        }

        // CSRF token example
        String csrfToken = UUID.randomUUID().toString();
        System.out.println("Generated CSRF Token: " + csrfToken);

        // Secure input example (escaping HTML to prevent XSS)
        String userInput = "<script>alert('XSS!')</script>";
        String escapedUserInput = StringEscapeUtils.escapeHtml4(userInput);
        System.out.println("Escaped User Input: " + escapedUserInput);

        // Example for SQL Injection prevention (parameterized query)
        try {
            // Assuming you have a valid JDBC connection object
            Connection connection = null;  // Replace with your actual connection
            String query = "SELECT * FROM users WHERE username = ?";
            PreparedStatement preparedStatement = connection.prepareStatement(query);
            String userInputForSQL = "admin"; // Simulating user input
            preparedStatement.setString(1, userInputForSQL);
            ResultSet resultSet = preparedStatement.executeQuery();

            // Processing the result set
            while (resultSet.next()) {
                System.out.println("User found: " + resultSet.getString("username"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}

