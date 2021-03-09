<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<!DOCTYPE html>
<html>
<head>
    <title>Java JSP Example</title>
</head>
<body>
<h1>Java JSP Example</h1>
<ul>
    <li><a href="version">DIDKit Version</a></li>
</ul>
<ul>
    <c:choose>
        <c:when test="${empty user}">
            <li><a href="${pageContext.request.contextPath}/sign-up.jsp">Sign Up</a></li>
            <li><a href="${pageContext.request.contextPath}/sign-in/user-password.jsp">Sign In with User/Password</a>
            </li>
            <li><a href="${pageContext.request.contextPath}/sign-in/verifiable-presentation.jsp">Sign In with
                VerifiablePresentation</a></li>
        </c:when>
        <c:otherwise>
            <li><a href="${pageContext.request.contextPath}/credential/authentication.jsp">Get Authentication
                Credential</a></li>
            <li><a href="${pageContext.request.contextPath}/credential/status.jsp">Get Status Credential</a></li>
            <li>
                <form method="post" action="${pageContext.request.contextPath}/sign-out">
                    <input type="submit" value="Logout"/>
                </form>
            </li>
        </c:otherwise>
    </c:choose>
</ul>
</body>
</html>